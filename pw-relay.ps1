#Requires -Version 5.1
<#
.SYNOPSIS
    パスワード中継ツール (PC側)。

.DESCRIPTION
    1. 公開中の暗号化ページが、このスクリプトに記録した内容と同じかを確かめる
    2. RSA 3072bit の鍵ペアをメモリ上にだけ作り、公開鍵入りのURLをクリップボードへ入れる
    3. 確認コードを表示する (相手のページにも同じものが出る。照合は任意)
    4. 相手から届いた暗号文 (PWR1:...) を復号し、履歴に残らない形でクリップボードへ入れる
    5. 貼り付けたら Enter。クリップボードを消去し、鍵を破棄する

    復号結果は画面・ファイル・ログのどこにも出力しない。
    Windows PowerShell 5.1 と .NET Framework の標準機能だけで動く。

.PARAMETER PageUrl
    docs/index.html を公開している GitHub Pages のURL。
    https:// のみ受け付ける (ローカルテスト用の http://localhost は例外)。

.PARAMETER ClearAfterSeconds
    復号結果をクリップボードに置いておく時間 (秒)。この時間が過ぎると自動で消去して終了する。
    待っている間に E キーで延長できる。0 を指定すると自動消去しない。

.PARAMETER SkipPageCheck
    公開ページの内容確認 (ハッシュ照合) を省略する。ネットワークの都合で確認できないとき専用。

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\pw-relay.ps1
#>
[CmdletBinding()]
param(
    [string]$PageUrl = 'https://ferrum-creative.github.io/pw-relay/',

    [ValidateRange(0, 3600)]
    [int]$ClearAfterSeconds = 60,

    [switch]$SkipPageCheck
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$KeyBits = 3072
$Prefix  = 'PWR1:'

# 公開ページ (docs/index.html、改行 LF) の SHA-256。ページを書き換えたら必ず更新する。
# 求め方は README の「ページを変更したとき」を参照。
$PinnedPageSha256 = '417780eba11d153b14dfc06149d4aa49c009eca3ac02b2bc99ac8789f42b1698'

Add-Type -AssemblyName System.Windows.Forms

function ConvertTo-Base64Url {
    param([byte[]]$Bytes)
    return [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function Get-Sha256 {
    param([byte[]]$Bytes)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return , $sha.ComputeHash($Bytes)
    } finally {
        $sha.Dispose()
    }
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

# 公開ページを取得してバイト列を返す。
# まず IPv4 を優先して直接つなぐ (接続待ちは1アドレスあたり3秒)。.NET Framework の WebClient は
# IPv6 のアドレスを先に1つずつ試すため、IPv6 がつながらない回線では起動に1分以上かかってしまう。
# 直接つなげない環境 (プロキシ必須など) では WebClient に切り替える。
function Get-PageBytes {
    param([Uri]$Uri)

    try {
        $addresses = @([System.Net.Dns]::GetHostAddresses($Uri.DnsSafeHost))
        $ordered = @($addresses | Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } | Select-Object -First 2) +
                   @($addresses | Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6 } | Select-Object -First 1)
        foreach ($address in $ordered) {
            $tcp = New-Object System.Net.Sockets.TcpClient -ArgumentList $address.AddressFamily
            try {
                $pending = $tcp.BeginConnect($address, $Uri.Port, $null, $null)
                if (-not $pending.AsyncWaitHandle.WaitOne(3000)) { continue }
                $tcp.EndConnect($pending)
                $tcp.ReceiveTimeout = 10000
                $tcp.SendTimeout = 10000

                $stream = $tcp.GetStream()
                if ($Uri.Scheme -eq 'https') {
                    # 証明書の検証は既定のまま (ホスト名と証明書チェーンを確認する)
                    $ssl = New-Object System.Net.Security.SslStream -ArgumentList $stream, $false
                    $ssl.AuthenticateAsClient($Uri.DnsSafeHost, $null, [System.Security.Authentication.SslProtocols]::Tls12, $false)
                    $stream = $ssl
                }

                # HTTP/1.0 で要求する (応答が分割転送にならず、本文をそのまま取り出せる)
                $request = "GET {0} HTTP/1.0`r`nHost: {1}`r`nAccept-Encoding: identity`r`nCache-Control: no-cache`r`nConnection: close`r`n`r`n" -f $Uri.PathAndQuery, $Uri.Authority
                $requestBytes = [System.Text.Encoding]::ASCII.GetBytes($request)
                $stream.Write($requestBytes, 0, $requestBytes.Length)
                $stream.Flush()

                $buffer = New-Object System.IO.MemoryStream
                $stream.CopyTo($buffer)
                $response = $buffer.ToArray()

                # ヘッダーと本文の境目 (CR LF CR LF) を探す
                $split = -1
                for ($i = 0; $i -le $response.Length - 4; $i++) {
                    if ($response[$i] -eq 13 -and $response[$i + 1] -eq 10 -and $response[$i + 2] -eq 13 -and $response[$i + 3] -eq 10) {
                        $split = $i
                        break
                    }
                }
                if ($split -lt 0) { continue }
                $header = [System.Text.Encoding]::ASCII.GetString($response, 0, $split)
                if ($header -notmatch '^HTTP/1\.[01] 200 ' -or $header -match '(?im)^Transfer-Encoding:') { continue }

                $body = New-Object byte[] ($response.Length - $split - 4)
                [Array]::Copy($response, $split + 4, $body, 0, $body.Length)
                return , $body
            } catch {
                continue
            } finally {
                $tcp.Close()
            }
        }
    } catch {
        # 下の WebClient に任せる
    }

    $client = New-Object System.Net.WebClient
    try {
        [System.Net.ServicePointManager]::SecurityProtocol =
            [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12
        $client.Headers['Cache-Control'] = 'no-cache'
        return , $client.DownloadData($Uri)
    } finally {
        $client.Dispose()
    }
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
# E キーで制限時間を延長する。$Seconds が 0 以下なら時間切れなし。
#
# 待っている間は 50 ミリ秒ごとにウィンドウメッセージを処理する。復号結果はこのプロセスが
# 保持したまま貼り付け要求に応じて渡す方式 (終了と同時に消える) なので、
# メッセージを処理しないと貼り付け先のアプリが固まる。
function Wait-EnterOrTimeout {
    param([int]$Seconds)

    $noLimit = ($Seconds -le 0)
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    $redirected = [Console]::IsInputRedirected
    $stdin = $null
    $buffer = $null
    $task = $null

    if ($redirected) {
        # 標準入力がパイプやファイルのとき (自動テスト用)。空行 = Enter、e で始まる行 = 延長
        $stdin = [Console]::OpenStandardInput()
        $buffer = New-Object byte[] 256
        $task = $stdin.ReadAsync($buffer, 0, $buffer.Length)
    } else {
        # 先に押されていたキーは捨てる (うっかり押した Enter で即消去されないように)
        while ([Console]::KeyAvailable) { [void][Console]::ReadKey($true) }
    }

    $shown = -1
    while ($true) {
        [System.Windows.Forms.Application]::DoEvents()

        $remain = [int][Math]::Ceiling(($deadline - [DateTime]::UtcNow).TotalSeconds)
        if (-not $noLimit -and $remain -le 0) {
            if (-not $redirected) { Write-Host '' }
            return $false
        }

        $action = $null
        if ($redirected) {
            if ($task.Wait(50)) {
                $count = $task.Result
                if ($count -gt 0 -and ($buffer[0] -eq 0x65 -or $buffer[0] -eq 0x45)) {
                    $action = 'extend'
                    $task = $stdin.ReadAsync($buffer, 0, $buffer.Length)
                } else {
                    $action = 'enter'
                }
            }
        } else {
            while ([Console]::KeyAvailable) {
                $key = [Console]::ReadKey($true).Key
                if ($key -eq [ConsoleKey]::Enter) { $action = 'enter' }
                elseif ($key -eq [ConsoleKey]::E -and $action -ne 'enter') { $action = 'extend' }
            }
            if (-not $noLimit -and $remain -ne $shown) {
                Write-Host ("`r    残り {0,4} 秒   [Enter] 消去して終了   [E] 延長 " -f $remain) -NoNewline
                $shown = $remain
            }
            Start-Sleep -Milliseconds 50
        }

        if ($action -eq 'enter') {
            if (-not $redirected) { Write-Host '' }
            return $true
        }
        if ($action -eq 'extend' -and -not $noLimit) {
            $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
        }
    }
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
$baseUrl  = ($PageUrl -split '#')[0]
$pageHost = ([Uri]$baseUrl).Authority

# 公開中のページが、記録してある内容と同じかを確かめる。
# GitHub アカウントの乗っ取りなどでページを書き換えられた場合に、ここで止まる。
# (確かめられるのはこの PC が受け取った内容だけ。相手のスマホに届く内容までは保証できない)
if ($SkipPageCheck) {
    Write-Host '注意: 公開ページの内容確認を省略しました (-SkipPageCheck)。' -ForegroundColor Yellow
} else {
    Write-Host '公開ページの内容を確認しています...'
    $pageBytes = $null
    try {
        $pageBytes = Get-PageBytes -Uri ([Uri]$baseUrl)
    } catch {
        Write-Host '公開ページを取得できませんでした。ネットワーク接続を確認してください。' -ForegroundColor Red
        Write-Host '  どうしても確認できない環境では -SkipPageCheck を付けると省略できます (安全性は下がります)。'
        exit 1
    }
    $pageHash = -join ((Get-Sha256 $pageBytes) | ForEach-Object { $_.ToString('x2') })
    if ($pageHash -cne $PinnedPageSha256.ToLowerInvariant()) {
        Write-Host '公開中のページが、このスクリプトに記録された内容と一致しません。使用を中止します。' -ForegroundColor Red
        Write-Host '  ・ページを更新した直後なら、反映まで 10 分ほど待ってからやり直してください。'
        Write-Host '  ・自分でページを書き換えたなら、$PinnedPageSha256 を更新してください (README 参照)。'
        Write-Host '  ・心当たりがなければ、ページが改ざんされた可能性があります。GitHub アカウントを確認してください。'
        exit 1
    }
}

# ---- 本体 ------------------------------------------------------------------

$rsa = $null
$secretOnClipboard = $false
$plainText = $null
$data = $null

try {
    # 1. 鍵ペアをメモリ上にだけ作る (名前なしの一時鍵。ディスクには保存されない)
    Write-Host '鍵を生成しています...'
    $rsa = New-Object System.Security.Cryptography.RSACng -ArgumentList $KeyBits
    $pub = $rsa.ExportParameters($false)
    $cipherBytes = $pub.Modulus.Length

    # 見張り役の別プロセスを起動する。このスクリプトが終了したとき (ウィンドウを × で閉じた、
    # 強制終了されたなど、finally が走らない場合を含む) に、復号結果がクリップボードに
    # 残っていれば消去する。一度でも貼り付けが行われるとデータは Windows 側に渡るため、
    # プロセスが消えるだけでは消えない。渡すのはプロセスIDと目印の名前だけで、秘密は渡さない。
    $marker = 'PwRelay-' + [Guid]::NewGuid().ToString('N')
    #
    # スクリプトが動いている間、クリップボードに目印があるかを 0.4 秒ごとに見ておき、
    # 「最後に見たとき目印があった」状態でスクリプトが終了したら消去する。
    # (終了後に目印を探しても見つからない。持ち主のプロセスが消えると、貼り付け済みの
    #  テキストだけが残り、目印は消えるため)
    $watchdog = "Add-Type -AssemblyName System.Windows.Forms; " +
                "`$seen = `$false; `$parent = Get-Process -Id $PID -ErrorAction SilentlyContinue; " +
                "while (`$parent -and -not `$parent.HasExited) { " +
                "try { `$seen = [System.Windows.Forms.Clipboard]::ContainsData('$marker') } catch { }; " +
                "Start-Sleep -Milliseconds 400 }; " +
                "if (`$seen) { for (`$i = 0; `$i -lt 30; `$i++) { " +
                "try { [System.Windows.Forms.Clipboard]::Clear(); break } catch { Start-Sleep -Milliseconds 100 } } }"
    $watchdogStarted = $false
    try {
        Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -WindowStyle Hidden `
            -ArgumentList "-NoProfile -STA -NonInteractive -Command $watchdog" | Out-Null
        $watchdogStarted = $true
    } catch {
        Write-Host '注意: 見張り役のプロセスを起動できませんでした。必ず Enter か Ctrl+C で終了してください' -ForegroundColor Yellow
        Write-Host '      (ウィンドウを × で閉じると、復号結果がクリップボードに残ることがあります)。' -ForegroundColor Yellow
    }

    # 2. 公開鍵入りのURLをクリップボードへ
    $url = '{0}#n={1}&e={2}' -f $baseUrl, (ConvertTo-Base64Url $pub.Modulus), (ConvertTo-Base64Url $pub.Exponent)
    try {
        [System.Windows.Forms.Clipboard]::SetDataObject($url, $true, 10, 100)
    } catch {
        Write-Host 'クリップボードを使えませんでした。画面がロックされていないか、リモート接続で' -ForegroundColor Red
        Write-Host 'クリップボードが禁止されていないかを確認して、もう一度実行してください。' -ForegroundColor Red
        exit 1
    }

    # 確認コード (modulus の SHA-256 の先頭16桁 = 64bit)。相手のページにも同じものが表示される
    $expectedCode = -join ((Get-Sha256 $pub.Modulus)[0..7] | ForEach-Object { $_.ToString('X2') })

    Write-Host ''
    Write-Host '[1] URLをクリップボードにコピーしました。Teams のチャットに貼り付けて相手に送ってください。'
    Write-Host ''
    Write-Host '    確認コード:  ' -NoNewline
    Write-Host (($expectedCode -split '(.{4})' | Where-Object { $_ }) -join ' ') -ForegroundColor Yellow
    Write-Host '    (相手のページにも同じコードが出ます。照合は任意です。URLが途中で書き換えられる'
    Write-Host '     心配があるときだけ、声で読み合わせてください)'
    Write-Host ''

    # 4. 暗号文を受け取って復号する。失敗したらやり直し
    while ($true) {
        Write-Host "[2] 相手から届いた暗号文 ($Prefix...) をコピーしてから Enter を押してください。"
        Write-Host '    Enter を押すと復号結果がクリップボードに入ります。画面共有中なら、先に止めてください。' -ForegroundColor Yellow
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

        # 5. 復号結果は画面に出さず、履歴に残らない形でクリップボードへ。
        #    平文はコマンドレットや関数の引数に渡さない (PowerShell のログ機能は引数を記録するため)。
        #    .NET のメソッド呼び出しだけで扱う。
        $decodeFailed = $false
        try {
            $plainText = [System.Text.UTF8Encoding]::new($false, $true).GetString($plainBytes)
        } catch {
            $decodeFailed = $true
        } finally {
            [Array]::Clear($plainBytes, 0, $plainBytes.Length)
        }
        if ($decodeFailed -or [regex]::IsMatch($plainText, '[\x00-\x1F\x7F]')) {
            $plainText = $null
            Write-Host '    復号結果に改行などの制御文字が含まれているため、破棄しました。' -ForegroundColor Yellow
            Write-Host '    もう一度暗号化して送ってもらってください。' -ForegroundColor Yellow
            Write-Host ''
            continue
        }

        # 溜まっているウィンドウメッセージを先に処理しておく。入力待ちの間に他のアプリが
        # クリップボードを書き換えると (暗号文のコピーがまさにそれ)、その通知が未処理のまま残る。
        # 残したまま下でセットすると、あとから通知が処理されて新しいデータのほうが無効になり、
        # 貼り付けても空になる。
        [System.Windows.Forms.Application]::DoEvents()

        $data = New-Object System.Windows.Forms.DataObject
        $data.SetData([System.Windows.Forms.DataFormats]::UnicodeText, $plainText)
        $plainText = $null
        # Win+V の履歴・クラウド同期・クリップボード監視ツールの対象から外す (DWORD 0 = 許可しない)
        foreach ($format in @('ExcludeClipboardContentFromMonitorProcessing',
                              'CanIncludeInClipboardHistory',
                              'CanUploadToCloudClipboard')) {
            $data.SetData($format, [System.IO.MemoryStream]::new([byte[]](0, 0, 0, 0)))
        }
        # 見張り役のプロセスが「これは pw-relay が入れたデータだ」と見分けるための目印
        $data.SetData($marker, [System.IO.MemoryStream]::new([byte[]](1)))
        $secretOnClipboard = $true
        # 第2引数 $false: データをこのプロセスが持ったままにし、貼り付け要求が来たときに渡す。
        # まだ一度も貼り付けられていなければ、プロセスが消えた時点で貼り付けできなくなる。
        [System.Windows.Forms.Clipboard]::SetDataObject($data, $false, 10, 100)
        break
    }

    Write-Host ''
    Write-Host '[3] 復号しました。パスワード欄にだけ貼り付けて (Ctrl+V) ください (チャット欄には貼らない)。' -ForegroundColor Green
    if ($watchdogStarted) {
        Write-Host '    Win+V の履歴とクラウド同期には残りません。このウィンドウを閉じた場合も自動で消去します。'
    } else {
        Write-Host '    Win+V の履歴とクラウド同期には残りません。'
    }
    if ($ClearAfterSeconds -gt 0) {
        Write-Host "    $ClearAfterSeconds 秒たつと自動で消去します。"
    } else {
        Write-Host '    貼り付けが終わったら Enter を押してください (クリップボードを消去して終了します)。'
    }
    Write-Host ''

    # 6. 貼り付けが済んだら消去 (実際の後始末は finally で行う)
    if (-not (Wait-EnterOrTimeout -Seconds $ClearAfterSeconds)) {
        Write-Host '    時間切れのため自動で消去します。' -ForegroundColor Yellow
    }
}
finally {
    # 7. Ctrl+C で中断されても必ずここを通る
    $plainText = $null
    if ($secretOnClipboard) {
        if (Clear-ClipboardQuietly) {
            Write-Host '消去済み: クリップボードを空にしました。' -ForegroundColor Green
        } else {
            Write-Host 'クリップボードを消去できませんでした。何か別の文字をコピーして上書きしてください。' -ForegroundColor Red
        }
    }
    $data = $null
    if ($null -ne $rsa) {
        $rsa.Dispose()
        Write-Host '鍵を破棄しました。'
    }
    [GC]::Collect()
}
