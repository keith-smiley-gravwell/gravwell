@echo off
REM Build the Gravwell Windows ingester MSI.
REM   gravwell.ico must be present in this directory.
REM   Set ELAM_DRIVER to the path of an MVI-signed ELAM driver to build a PPL-capable
REM   package (see THREAT_INTELLIGENCE.md); leave it unset otherwise.
set VERSION=5.10.3
set CGO_ENABLED=0
set GOOS=windows
set GOARCH=amd64
go build -o gravwell_windows.exe . || exit /b 1
set ELAMDEF=
if defined ELAM_DRIVER set ELAMDEF=-dELAM_DRIVER="%ELAM_DRIVER%"
"%wix%"\bin\candle -arch x64 -ext WixUtilExtension LicenseAgreementDlg_HK.wxs ConfigurationDlg.wxs WixUI_HK.wxs product.wxs -dVersion=%VERSION% %ELAMDEF% || exit /b 1
"%wix%"\bin\light -cultures:en-us -loc en-us.wxl -ext WixUIExtension -ext WixUtilExtension -sacl -spdb -out gravwell_windows_%VERSION%.msi LicenseAgreementDlg_HK.wixobj WixUI_HK.wixobj product.wixobj ConfigurationDlg.wixobj || exit /b 1
