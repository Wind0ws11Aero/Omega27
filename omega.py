import platform
import sys
import click
import asyncio

from goldennugget import FileToRestore, restore_files
from pymobiledevice3.exceptions import NoDeviceConnectedError
from pymobiledevice3.lockdown import create_using_usbmux
from pathlib import Path

def exit(code=0):
    if platform.system() == "Windows" and getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        input("Press Enter to exit...")

    sys.exit(code)

async def get_device_info(client):
    os_names = {
        "iPhone": "iOS",
        "iPad": "iPadOS",
        "iPod": "iOS",
        "RealityDevice": "visionOS",
    }
    device_class = await client.get_value(key="DeviceClass")
    product_version = await client.get_value(key="ProductVersion")
    info_text = f"{await client.get_value(key="DeviceName")} ({(os_names[device_class] + " " + product_version) if device_class in os_names else ""})"
    return info_text

async def main():
    try:
        lockdown = await create_using_usbmux()
    except NoDeviceConnectedError:
            click.secho("No device detected! Please connect your device via USB and try again.", fg="red")
            exit(1)

    click.secho("Omega v1.0 - by jailbreak.party\nMade possible by JJTech (@JJTech0130), Duy Tran (@khanhduytran0) and Mineek (@mineekdev)", fg="blue")
    click.secho(f"Connected to {await get_device_info(lockdown)}", fg="green")
    try:
        product_version = await lockdown.get_value(key="ProductVersion") or ""
    except Exception:
        product_version = ""

    click.secho("This will clear the app revokes and certificate validity databases.", fg="yellow")
    click.secho("NOTE: This tool is experimental and has a chance of damaging your device, or causing data loss.\nWe take zero responsibility in the event this happens. Use this tool at your own risk.", fg="red")

    while True:
            value = input("To continue, type \"CONTINUE\" and hit Enter. Otherwise, the script will exit.\n").strip()
            if value == "CONTINUE":
                cloudconfig_path = Path.joinpath(Path.cwd(), "files/CloudConfigurationDetails.plist")
                cloudconfig_contents = open(cloudconfig_path, "rb").read()

                purplebuddy_path = Path.joinpath(Path.cwd(), "files/com.apple.purplebuddy.plist")
                purplebuddy_contents = open(purplebuddy_path, "rb").read()

                files = [
                    # unrevoke placeholders: emptying these DBs clears the app
                    # revokes + certificate validity lists (root-owned, as before)
                    FileToRestore(contents=b"", restore_path="MobileIdentityData/Rejections.plist", domain="DatabaseDomain", owner=0, group=0),
                    FileToRestore(contents=b"", restore_path="MobileIdentityData/AuthListBannedUpps.plist", domain="DatabaseDomain", owner=0, group=0),
                    FileToRestore(contents=b"", restore_path="MobileIdentityData/AuthListBannedCdHashes.plist", domain="DatabaseDomain", owner=0, group=0),
                    FileToRestore(contents=b"", restore_path="trustd/valid.sqlite3", domain="ProtectedDomain", owner=0, group=0),
                    FileToRestore(contents=b"", restore_path="trustd/valid.sqlite3-shm", domain="ProtectedDomain", owner=0, group=0),
                    FileToRestore(contents=b"", restore_path="trustd/valid.sqlite3-wal", domain="ProtectedDomain", owner=0, group=0),
                    # skip setup
                    FileToRestore(contents=cloudconfig_contents, restore_path="Library/ConfigurationProfiles/CloudConfigurationDetails.plist", domain="SysSharedContainerDomain-systemgroup.com.apple.configurationprofiles", owner=0, group=0),
                    FileToRestore(contents=purplebuddy_contents, restore_path="mobile/com.apple.purplebuddy.plist", domain="ManagedPreferencesDomain", owner=0, group=0),
                ]

                # iOS 27 hardening notice (grounded in the 26.6.2 -> 27.0 diff):
                # trustd gained _SecFixTrustdFilePermissions + new revocation
                # policy checks, and BackupAgent2 now hardens file ownership
                # (_fchownat/_fcopyfile). The ProtectedDomain/trustd and
                # DatabaseDomain/MobileIdentityData "unrevoke" placeholders are
                # very likely REJECTED (ErrorCode 205) or self-healed, so
                # clearing app revokes may not take effect. Skip-setup still works.
                try:
                    major = int((product_version.split(".")[0]) if product_version else "0")
                except Exception:
                    major = 0
                if major >= 27:
                    click.secho(
                        "iOS 27 detected: trustd now self-repairs its validity DB "
                        "(_SecFixTrustdFilePermissions) and re-checks revocation with "
                        "a new policy, while BackupAgent2 hardens restore-time file "
                        "ownership. The trustd/MobileIdentityData 'unrevoke' trick is "
                        "very likely REJECTED or self-healed - app-revoke clearing may "
                        "NOT persist. Skip-setup (configurationprofiles / purplebuddy) "
                        "still applies.", fg="yellow")

                click.secho("Running six-phase restore (protective backup -> tweaks -> wipe -> restore -> skip setup)...", fg="yellow")
                try:
                    await restore_files(
                        files,
                        reboot=True,
                        lockdown_client=lockdown,
                        progress_callback=lambda s: click.secho(f"{s}\r", fg="green"),
                        skip_setup=True,
                        merge_phases=False,
                    )
                except Exception as e:
                    click.secho(f"Restore failed: {e}", fg="red")
                    click.secho("Your protective backup is kept on this computer for a later restore.", fg="yellow")
                    exit(1)
                click.secho("Finished! Your device should reboot shortly. If it does not, you may reboot it manually.")
            click.secho("Exiting script...", fg="red")
            exit()

if __name__ == "__main__":
    asyncio.run(main())
