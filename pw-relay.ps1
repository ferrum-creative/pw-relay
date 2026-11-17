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
    https:// のみ受け付ける (ローカルテスト用の http://localhost は例外)。

.PARAMETER ClearAfterSeconds
    復号結果をクリップボードに置いておく最長時間 (秒)。Enter を押さなくても、
    この時間が過ぎると自動で消去して終了する。0 を指定すると自動消去しない。

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\pw-relay.ps1 -PageUrl https://example.github.io/pw-relay/
#>
[CmdletBinding()]
param(
    [string]$PageUrl = 'https://ferrum-creative.github.io/pw-relay/',

    [ValidateRange(0, 3600)]
    [int]$ClearAfterSeconds = 60
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
    # 消去できないときは、せめて無害な文字で上書きを試みる
    try {
        [System.Windows.Forms.Clipboard]::SetDataObject(' ', $true, 10, 100)
        return $true
    } catch {
        return $false
    }
}

# Enter が押されるか制限時間が過ぎるまで待つ。Enter なら $true、時間切れなら $false。
# 短い間隔で区切って待つので、途中の Ctrl+C にもすぐ反応する。
function Wait-EnterOrTimeout {
    param([int]$Seconds)

    if ($Seconds -le 0) {
        [void](Read-Host '    Enter で消去して終了')
        return $true
    }
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)

    if ([Console]::IsInputRedirected) {
        # 標準入力がパイプやファイルのとき (自動テスト用)
        $buffer = New-Object byte[] 256
        $task = [Console]::OpenStandardInput().ReadAsync($buffer, 0, $buffer.Length)
        while ([DateTime]::UtcNow -lt $deadline) {
            if ($task.Wait(200)) { return $true }
        }
        return $false
    }

    # 先に押されていたキーは捨てる (うっかり押した Enter で即消去されないように)
    while ([Console]::KeyAvailable) { [void][Console]::ReadKey($true) }
    while ([DateTime]::UtcNow -lt $deadline) {
        while ([Console]::KeyAvailable) {
            if ([Console]::ReadKey($true).Key -eq [ConsoleKey]::Enter) { return $true }
        }
        Start-Sleep -Milliseconds 100
    }
    return $false
}

# ---- 事前チェック ----------------------------------------------------------

if ([Threading.Thread]::CurrentThread.GetApartmentState() -ne [Threading.ApartmentState]::STA) {
    Write-Host 'クリップボードを使うには STA モードが必要です。powershell.exe から (-MTA を付けずに) 実行してください。' -ForegroundColor Red
    exit 1
}
if ($PageUrl -notmatch '^(https://|http://(localhost|127\.0\.0\.1)(:\d+)?/)') {
    Write-Host '暗号化ページのURLは https:// で始まる必要があります (http では配信途中でページを書き換えられるため)。' -ForegroundColor Red
    Write-Host '  -PageUrl https://<アカウント名>.github.io/pw-relay/ を付けて実行するか、'
    Write-Host '  スクリプト冒頭の param の既定値を https:// のURLに書き換えてください。'
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

    # 3. 指紋 (modulus の SHA-256 の先頭16桁 = 64bit)。
    #    8桁 (32bit) では、同じ指紋になる偽の鍵を短時間で作れてしまう
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha.ComputeHash($pub.Modulus)
    } finally {
        $sha.Dispose()
    }
    $hex = -join ($hash[0..7] | ForEach-Object { $_.ToString('X2') })
    $fingerprint = ($hex -split '(.{4})' | Where-Object { $_ }) -join ' '

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

        # 暗号文が2つ以上あるときは、どれを使うか決めつけずにやり直してもらう
        if ([regex]::Matches([string]$clip, [regex]::Escape($Prefix)).Count -gt 1) {
            $clip = $null
            Write-Host "    クリップボードに暗号文 ($Prefix...) が複数含まれています。" -ForegroundColor Yellow
            Write-Host '    相手が最後に送った1つだけをコピーし直してください。' -ForegroundColor Yellow
            Write-Host ''
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
    if ($ClearAfterSeconds -gt 0) {
        Write-Host "    貼り付けが終わったら Enter を押してください。押さなくても $ClearAfterSeconds 秒後に自動で消去します。"
    } else {
        Write-Host '    貼り付けが終わったら Enter を押してください (クリップボードを消去して終了します)。'
    }
    if (-not (Wait-EnterOrTimeout -Seconds $ClearAfterSeconds)) {
        Write-Host "    $ClearAfterSeconds 秒たったので自動で消去します。" -ForegroundColor Yellow
    }
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
