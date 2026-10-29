# PacketCapture

PacketCapture is a small tool that records game network traffic while you play. These recordings help us develop TOSS, a community-run, non-commercial game server, by showing us how the original game works. They also help us preserve player accounts, progress, and club worlds.

## How it works

1. PacketCapture uses Windows' built-in packet monitor (`pktmon`) to record traffic to and from the game's servers. It filters by server address, so unrelated network traffic isn't captured.
2. Launch the game and play as usual. PacketCapture runs separately from the game. It doesn't inject anything, access game memory, or interfere with the game itself.
3. Once you're finished, PacketCapture packages the recording into a zip file, along with some basic information like your title, notes, completed checklist items, game version, timestamps, and the servers you connected to.
4. If you've linked your Discord account using `/capture <code>` in the TOSS Discord, you can upload the recording directly. Otherwise, the zip is saved locally, and you can upload it later by dragging it onto the executable.

PacketCapture needs administrator permission to run because Windows requires it for `pktmon`.

## Privacy

We want to be clear about what PacketCapture collects and what happens to your recordings.

- **When you open PacketCapture**, it checks the submission server for the latest capture settings and app version. These settings include the game's server addresses, ports, process names, recording checklists, and interface text. These requests don't send any information about you or your PC.
- **Uploads are optional.** PacketCapture only uploads recordings after you've linked your Discord account, and you choose which recordings to submit.

## Building

You'll need Windows and the .NET SDK (8 or newer). You'll also need the .NET Framework 4.8 targeting pack, which is included with Visual Studio or the Visual Studio Build Tools.

```bash
dotnet build -c Release -o build
```

## Usage

Run `PacketCapture` without any arguments to open the interactive interface. From there, you can choose what to record, link your Discord account, start a recording, and upload it when you're done.

## License

MIT. See [LICENSE](LICENSE).
