"""Every check the agent can run. Adding a check means adding it to ALL_CHECKS."""

from __future__ import annotations

from sentinel_core.checks import Check

from .common.dependencies import ProjectDependencies
from .common.network import DnsConfiguration, ListeningPorts, NetworkInterfaces, SuspiciousProcessLocations, UnusualOutbound
from .common.resources import ResourceDiagnostics
from .linux.authlog import LinuxAuthLog
from .linux.packages import LinuxPackages
from .linux.ssh import SshServerConfig
from .linux.system import LinuxAccounts, LinuxFirewall
from .linux.updates import LinuxUpdates, UnattendedUpgrades
from .malware.clamav import ClamAvScan
from .network.headers import HttpHeaders
from .network.nmap import NmapDiscovery
from .network.tls import TlsCertificate
from .windows.accounts import LocalAccounts
from .windows.bitlocker import BitLockerEncryption
from .windows.defender import DefenderStatus
from .windows.eventlogs import WindowsDefenderLog, WindowsSecurityLog, WindowsSystemLog
from .windows.firewall import FirewallProfiles
from .windows.hardening import LsaProtection, SmartScreen
from .windows.inventory import WindowsOsInventory, WindowsSoftwareInventory
from .windows.network_profile import NetworkProfile
from .windows.password_policy import PasswordPolicy
from .windows.rdp import RemoteDesktop
from .windows.secureboot import SecureBoot
from .windows.startup import StartupPrograms
from .windows.uac import UacConfiguration
from .windows.updates import WindowsUpdates

ALL_CHECKS: list[type[Check]] = [
    # reference checks
    ResourceDiagnostics,
    FirewallProfiles,
    UacConfiguration,
    # Windows posture
    WindowsUpdates,
    DefenderStatus,
    RemoteDesktop,
    LocalAccounts,
    StartupPrograms,
    LsaProtection,
    BitLockerEncryption,
    SecureBoot,
    PasswordPolicy,
    SmartScreen,
    NetworkProfile,
    # posture on both operating systems
    ListeningPorts,
    SuspiciousProcessLocations,
    UnusualOutbound,
    DnsConfiguration,
    NetworkInterfaces,
    # Linux posture
    LinuxUpdates,
    UnattendedUpgrades,
    SshServerConfig,
    LinuxFirewall,
    LinuxAccounts,
    # inventory
    WindowsSoftwareInventory,
    WindowsOsInventory,
    LinuxPackages,
    ProjectDependencies,
    # logs
    WindowsSecurityLog,
    WindowsSystemLog,
    WindowsDefenderLog,
    LinuxAuthLog,
    # network (need parameters)
    NmapDiscovery,
    TlsCertificate,
    HttpHeaders,
    # malware (needs configured folders)
    ClamAvScan,
]
