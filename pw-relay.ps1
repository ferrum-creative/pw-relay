#Requires -Version 5.1
<#
.SYNOPSIS
    パスワード中継ツール (PC側)。

.DESCRIPTION
    1. RSA 3072bit の鍵ペアをメモリ上にだけ作り、公開鍵入りのURLをクリップボードへ入れる
    2. 相手がそのURLのページでパスワードを暗号化し、暗号文 (PWR1:...) を送り返す
    3. 暗号文をコピーして Enter を押すと復号し、結果を「履歴に残らない形」でクリップボードへ入れる
    4. 貼り付けたら Enter。クリップボードを消去し、鍵を破棄する

    復号結果は画面・ファイル・ログのどこにも出力しない。
    Windows PowerShell 5.1 と .NET Framework の標準機能だけで動く。

.PARAMETER PageUrl
    docs/index.html を公開している GitHub Pages のURL。
    毎回指定するのが面倒なら、下の param の既定値を書き換える。

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\pw-relay.ps1 -PageUrl https://example.github.io/pw-relay/
#>
[CmdletBinding()]
param(
    [string]$PageUrl = 'https://YOUR-ACCOUNT.github.io/pw-relay/'
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$KeyBits = 3072
$Prefix  = 'PWR1:'

Add-Type -AssemblyName System.Windows.Forms

function ConvertTo-Base64Url {
    param([byte[]]$Bytes)
    return [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

# クリップボードの文字列から "PWR1:<base64>" を探し、暗号文のバイト列を返す。
# 見つからなければ $null。チャット経由で混ざる改行・空白・ゼロ幅文字は取り除く。
function Find-Ciphertext {
    param([string]$Text, [int]$CipherBytes)

    if ([string]::IsNullOrEmpty($Text)) { return $null }
    $start = $Text.IndexOf($Prefix, [StringComparison]::Ordinal)
    if ($start -lt 0) { return $null }

    $rest = $Text.Substring($start + $Prefix.Length)
    $rest = [regex]::Replace($rest, '[\s​-‍⁠﻿]', '')

    # 暗号文は鍵長と同じバイト数なので、base64 の文字数も決まっている
    $rem = $CipherBytes % 3
    $needChars = [int][Math]::Floor($CipherBytes / 3) * 4
    if ($rem -ne 0) { $needChars += $rem + 1 }

    $m = [regex]::Match($rest, '^[A-Za-z0-9+/_-]+')
    if (-not $m.Success -or $m.Value.Length -lt $needChars) { return $null }

    $b64 = $m.Value.Substring(0, $needChars).Replace('-', '+').Replace('_', '/')
    while ($b64.Length % 4 -ne 0) { $b64 += '=' }
    try {
        $bytes = [Convert]::FromBase64String($b64)
    } catch {
        return $null
    }
    return , $bytes
}

# Win+V の履歴・クラウド同期・クリップボード監視ツールの対象から外して文字列を格納する
function Set-SecretClipboard {
    param([string]$Text)

    $data = New-Object System.Windows.Forms.DataObject
    $data.SetData([System.Windows.Forms.DataFormats]::UnicodeText, $Text)
    $zero = [byte[]](0, 0, 0, 0)   # DWORD 0 = 許可しない
    foreach ($format in @('ExcludeClipboardContentFromMonitorProcessing',
                          'CanIncludeInClipboardHistory',
                          'CanUploadToCloudClipboard')) {
        $data.SetData($format, [System.IO.MemoryStream]::new($zero))
    }
    [System.Windows.Forms.Clipboard]::SetDataObject($data, $true, 10, 100)
}

function Clear-ClipboardQuietly {
    for ($i = 0; $i -lt 10; $i++) {
        try {
            [System.Windows.Forms.Clipboard]::Clear()
            return $true
        } catch {
            Start-Sleep -Milliseconds 100
        }
    }
    return $false
}

# ---- 事前チェック ----------------------------------------------------------

if ([Threading.Thread]::CurrentThread.GetApartmentState() -ne [Threading.ApartmentState]::STA) {
    Write-Host 'クリップボードを使うには STA モードが必要です。powershell.exe から (-MTA を付けずに) 実行してください。' -ForegroundColor Red
    exit 1
}
if ($PageUrl -match 'YOUR-ACCOUNT' -or $PageUrl -notmatch '^https?://') {
    Write-Host '暗号化ページのURLが設定されていません。' -ForegroundColor Red
    Write-Host '  -PageUrl https://<アカウント名>.github.io/pw-relay/ を付けて実行するか、'
    Write-Host '  スクリプト冒頭の param の既定値を書き換えてください。'
    exit 1
}
$baseUrl = ($PageUrl -split '#')[0]

# ---- 本体 ------------------------------------------------------------------

$rsa = $null
$secretOnClipboard = $false
$plainText = $null

try {
    # 1. 鍵ペアをメモリ上にだけ作る (名前なしの一時鍵。ディスクには保存されない)
    Write-Host '鍵を生成しています...'
    $rsa = New-Object System.Security.Cryptography.RSACng -ArgumentList $KeyBits
    $pub = $rsa.ExportParameters($false)
    $cipherBytes = $pub.Modulus.Length

    # 2. 公開鍵入りのURLをクリップボードへ
    $url = '{0}#n={1}&e={2}' -f $baseUrl, (ConvertTo-Base64Url $pub.Modulus), (ConvertTo-Base64Url $pub.Exponent)
    [System.Windows.Forms.Clipboard]::SetDataObject($url, $true, 10, 100)

    # 3. 指紋 (modulus の SHA-256 の先頭8桁)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha.ComputeHash($pub.Modulus)
    } finally {
        $sha.Dispose()
    }
    $hex = -join ($hash[0..3] | ForEach-Object { $_.ToString('X2') })
    $fingerprint = $hex.Substring(0, 4) + ' ' + $hex.Substring(4, 4)

    Write-Host ''
    Write-Host '[1] URLをクリップボードにコピーしました。Teams のチャットに貼り付けて相手に送ってください。'
    Write-Host ''
    Write-Host '    確認コード:  ' -NoNewline
    Write-Host $fingerprint -ForegroundColor Yellow
    Write-Host ''
    Write-Host '    相手のページに表示される確認コードを読み上げてもらい、上と一致することを確かめてください。'
    Write-Host '    一致しない場合は中止してください (Ctrl+C)。'
    Write-Host ''

    # 4. 暗号文を受け取って復号する。失敗したらやり直し
    while ($true) {
        Write-Host "[2] 相手から届いた暗号文 ($Prefix...) をコピーしてから Enter を押してください。"
        [void](Read-Host '    Enter で復号')

        $clip = $null
        try {
            $clip = [System.Windows.Forms.Clipboard]::GetText()
        } catch {
            Write-Host '    クリップボードを読み取れませんでした。もう一度お試しください。' -ForegroundColor Yellow
            continue
        }

        $cipher = Find-Ciphertext -Text $clip -CipherBytes $cipherBytes
        $clip = $null
        if ($null -eq $cipher) {
            Write-Host "    クリップボードに暗号文が見つかりません (または途中で切れています)。" -ForegroundColor Yellow
            Write-Host "    $Prefix から最後の文字までコピーし直してください。" -ForegroundColor Yellow
            Write-Host ''
            continue
        }

        $plainBytes = $null
        try {
            $plainBytes = $rsa.Decrypt($cipher, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
        } catch {
            Write-Host '    復号できませんでした。暗号文が壊れているか、別のURL (別の鍵) で暗号化されています。' -ForegroundColor Yellow
            Write-Host '    今回送ったURLのページで、もう一度暗号化してもらってください。' -ForegroundColor Yellow
            Write-Host ''
            continue
        }
        if ($null -eq $plainBytes -or $plainBytes.Length -eq 0) {
            Write-Host '    復号結果が空でした。もう一度暗号化してもらってください。' -ForegroundColor Yellow
            Write-Host ''
            continue
        }

        # 5. 復号結果は画面に出さず、履歴に残らない形でクリップボードへ
        try {
            $plainText = [System.Text.Encoding]::UTF8.GetString($plainBytes)
        } finally {
            [Array]::Clear($plainBytes, 0, $plainBytes.Length)
        }
        $secretOnClipboard = $true
        Set-SecretClipboard -Text $plainText
        $charCount = (New-Object System.Globalization.StringInfo -ArgumentList $plainText).LengthInTextElements
        $plainText = $null
        break
    }

    Write-Host ''
    Write-Host "[3] 復号しました ($charCount 文字)。クリップボードに入っています。" -ForegroundColor Green
    Write-Host '    ログイン画面のパスワード欄に貼り付けて (Ctrl+V) ください。'
    Write-Host '    Win+V の履歴とクラウド同期には残りません。'
    Write-Host ''

    # 6. 貼り付けが済んだら消去 (実際の後始末は finally で行う)
    [void](Read-Host '    貼り付けが終わったら Enter (クリップボードを消去して終了します)')
}
finally {
    # 7. Ctrl+C で中断されても必ずここを通る
    $plainText = $null
    if ($secretOnClipboard) {
        if (Clear-ClipboardQuietly) {
            Write-Host 'クリップボードを消去しました。'
        } else {
            Write-Host 'クリップボードを消去できませんでした。何か別の文字をコピーして上書きしてください。' -ForegroundColor Red
        }
    }
    if ($null -ne $rsa) {
        $rsa.Dispose()
        Write-Host '鍵を破棄しました。'
    }
    [GC]::Collect()
}
