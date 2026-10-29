# PacketCapture

PacketCapture records a game's network traffic while you play, so you can contribute it to TOSS, a community-run,
non-commercial game server. Recordings teach the server how the game behaves, and preserve your account progress and
club worlds.

## What it does

1. It starts Windows' built-in packet monitor, **pktmon**, filtered to the game's server addresses. Only connections to
   those servers are recorded. Nothing else on your PC is captured.
2. You launch the game and play normally. PacketCapture never touches the game: nothing is injected, nothing runs
   inside it, and its memory is never read.
3. When you're done, it zips the recording with a small metadata file. The metadata holds the title and notes you typed,
   the steps you ticked, the version, the times, and which servers the game connected to.
4. If you've linked your Discord account (`/capture <code>` in the TOSS Discord), it uploads the zip. Otherwise it keeps
   the zip, and you can upload it later by dragging it onto the exe.

Windows asks for admin permission when you start it, because pktmon requires it.

## Privacy

- **When it starts**, PacketCapture asks the submission server for its capture profile and checks for a newer version.
  The profile lists the game's server addresses, ports and process names, the recording checklists, and the app's text.
  These requests send nothing about you or your PC.
- **The recording** includes the game's login handshake. The submission server strips the login data as soon as an
  upload arrives, before the recording is stored: the login ticket and its signature, and the game's anti-cheat
  responses. Your account's email address is kept with the recording, so nobody can claim someone else's account with it.
- **Uploads** only happen after you link your Discord account, and only for the recordings you choose to send.

## Building

You need Windows with the .NET SDK (8 or later). The .NET Framework 4.8 targeting pack comes with Visual Studio or
the Build Tools.

```
dotnet build -c Release -o build
```

The result is one file, `build/PacketCapture.exe` (about 65 KB). It runs on the .NET Framework 4.8 that comes with
Windows 10 (1903 and later) and 11, so nothing else needs installing.

## Usage

```
PacketCapture                     interactive: choose what to record, link Discord, record, upload
PacketCapture --mode account      start straight in a mode (general | account | club)
PacketCapture --upload <zip>      upload, or resume uploading, a recording made earlier
PacketCapture --endpoint <url>    use another submission server
```

## License

MIT, see [LICENSE](LICENSE).
