$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Speech
$demoRoot = $PSScriptRoot
$demoScenes = Get-Content -LiteralPath (Join-Path $demoRoot 'scenes.json') -Raw | ConvertFrom-Json
$demoVoice = New-Object System.Speech.Synthesis.SpeechSynthesizer
$demoVoice.SelectVoice('Microsoft Zira Desktop')
$demoVoice.Rate = 0
$demoIndex = 0
foreach ($demoScene in $demoScenes) {
    $demoPath = Join-Path $demoRoot ('out/voice-{0:d2}.wav' -f $demoIndex)
    $demoVoice.SetOutputToWaveFile($demoPath)
    $demoVoice.Speak($demoScene.narration)
    $demoVoice.SetOutputToNull()
    $demoIndex++
}
$demoVoice.Dispose()
Write-Output 'SAPI narration generated: Microsoft Zira Desktop; local synthesis only.'
