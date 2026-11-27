import 'package:flutter/material.dart';
import 'package:mobile_scanner/mobile_scanner.dart';

/// Reads a QR code with the camera and returns its text. Nothing is opened.
class QrScannerScreen extends StatefulWidget {
  const QrScannerScreen({super.key});

  @override
  State<QrScannerScreen> createState() => _QrScannerScreenState();
}

class _QrScannerScreenState extends State<QrScannerScreen> {
  final _controller = MobileScannerController(formats: const [BarcodeFormat.qrCode]);
  String? _found;

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  void _onDetect(BarcodeCapture capture) {
    if (_found != null) return;
    final value = capture.barcodes.map((b) => b.rawValue).whereType<String>().firstOrNull;
    if (value == null || value.isEmpty) return;
    setState(() => _found = value);
    _controller.stop();
  }

  @override
  Widget build(BuildContext context) {
    final found = _found;
    return Scaffold(
      appBar: AppBar(title: const Text('Scan a QR code')),
      body: Column(
        children: [
          Expanded(
            child: found == null
                ? MobileScanner(
                    controller: _controller,
                    onDetect: _onDetect,
                    errorBuilder: (context, error) => Center(
                      child: Padding(
                        padding: const EdgeInsets.all(24),
                        child: Text(
                          error.errorCode == MobileScannerErrorCode.permissionDenied
                              ? 'Allow camera access in your phone settings to scan QR codes.'
                              : "The camera isn't available.",
                          textAlign: TextAlign.center,
                        ),
                      ),
                    ),
                  )
                : Padding(
                    padding: const EdgeInsets.all(24),
                    child: Column(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        const Icon(Icons.qr_code_2, size: 56),
                        const SizedBox(height: 12),
                        const Text('This QR code contains:'),
                        const SizedBox(height: 6),
                        SelectableText(found, textAlign: TextAlign.center),
                        const SizedBox(height: 8),
                        const Text("Don't open it yet — check it first."),
                      ],
                    ),
                  ),
          ),
          SafeArea(
            minimum: const EdgeInsets.all(16),
            child: found == null
                ? const Text(
                    'Point the camera at the QR code. The picture stays on your phone.',
                    textAlign: TextAlign.center,
                  )
                : Row(
                    children: [
                      Expanded(
                        child: OutlinedButton(
                          onPressed: () {
                            setState(() => _found = null);
                            _controller.start();
                          },
                          child: const Text('Scan again'),
                        ),
                      ),
                      const SizedBox(width: 12),
                      Expanded(
                        child: FilledButton(
                          onPressed: () => Navigator.of(context).pop(found),
                          child: const Text('Check it'),
                        ),
                      ),
                    ],
                  ),
          ),
        ],
      ),
    );
  }
}
