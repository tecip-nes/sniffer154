Sniffer 15.4
==========

## Introduction


Sniffer 15.4 is the first Android App that lets you sniff IEEE 802.15.4 packets directly from your phone. 

It allows interfacing an IEEE 802.15.4 sniffing device with an Android smartphone or tablet. The sniffing device captures frames over the air and sends the raw data to the smartphone. The actual packet analysis is done on the Android device. Sniffer 15.4  advantages over existing solutions are:

* mobility: the system is particularly suitable for testing on the field;
* ease of use: just plug the sniffer in the Android device USB port and play;

## Sniffer 15.4 Features

* Capture 802.15.4 frames (by using the sniffer 15.4 accessory/device)
* Display captured frames
* Filtering (by frame type, source address, destination address, and payload)
* Store captured frames on phone memory for future display
* Export captured frames to PCAP format (Wireshark compatible)
* Live forwarding to an arbitrary IP address using the Zigbee Encapsulation Protocol (ZEP) (live forwarding allows you to analyze captured frames using your favorite packet analyzer, e.g., Wireshark)
* Test mode (to try out application functionality without the sniffer 15.4 accessory)

## Sniffing hardware

Sniffer 15.4 requires external hardware to actually capture IEEE 802.15.4 frames. Such hardware can be a sniffer device or a sniffer accessory (for the definition of accessory see the [Android documentation](http://developer.android.com/guide/topics/connectivity/usb/accessory.html)). If your Android device supports the USB host mode, you can use either a sniffer accessory or a sniffer device. However, if your Android device does not support the USB host mode, you must use a sniffer accessory.

### Sniffer 15.4 accessory

The Sniffer 15.4 Accessory is a [SEED-EYE board](http://rtn.sssup.it/index.php/research-activities/51) running a special firmware we developed (see below for the binary and the source code). Such firmware turns the board into an Android USB Accessory and allows using the on-board transceiver to sniff IEEE 802.15.4 networks.

The board can be purchased from Evidence S.r.l, a spin-off of Scuola Superiore Sant'Anna:
http://www.evidence.eu.com/products/seed-eye.html

### Sniffer 15.4 device

The Sniffer 15.4 Device is a [Tmote Sky](http://www.snm.ethz.ch/Projects/TmoteSky) running a special firmware we developed (see below for the binary and the source code). It must be connected to the Android device using a USB OTG cable.

## Downloads

Sniffer 15.4 App: get it directly from [Google Play](https://play.google.com/store/apps/details?id=it.sssup.rtn.sniffer154)

Sniffer 15.4 Documentation (outdated): http://retis.sssup.it/~daniele/Sniffer15.4-UserManual.pdf

Firmware for the SEED-EYE board (Sniffer 15.4 Accessory): [ELF](http://retis.sssup.it/~daniele/android-sniffer/seedeye-android-sniffer.elf) or [HEX](http://retis.sssup.it/~daniele/android-sniffer/seedeye-android-sniffer.hex)

Firmware for the Tmote Sky (Sniffer 15.4 Device): [ELF](http://retis.sssup.it/~daniele/android-sniffer/sniffer.sky)

## Source code

The source code for the SEED-EYE firmware (Sniffer 15.4 Accessory) can be found [here](http://retis.sssup.it/~daniele/android-sniffer/seedeye-android-sniffer.tar.bz2). The code must be compiled using [this version](http://retis.sssup.it/~daniele/android-sniffer/ee.tar.bz2) of the Erika real-time operating system.

The source code for the Tmote Sky (Sniffer 15.4 Device) is hosted on GitHub: https://github.com/alessandrelli/contiki-sssup/tree/android-sniffer

The source code of the Android application is hoseted on Github as well: https://github.com/tecip-nes/sniffer154 [But, if you are reading this, you proabaly already know ;)]

## Credits

Sniffer 15.4 App - Developed by Daniele Alessandrelli and Andrea Azzarà. The app uses a [modified version](https://github.com/alessandrelli/usb-serial-for-android) of the [usb-serial-for-android library](http://code.google.com/p/usb-serial-for-android/) by Mike Wakerly.

Sniffer 15.4 Accessory - Developed by Daniele Alessandrelli and Andrea Azzarà. Based on [Erika RTOS](http://erika.tuxfamily.org/).

Sniffer 15.4 Device - Developed by Daniele Alessandrelli. Based on [Contiki OS](http://www.contiki-os.org/).

## Contacts

For further information feel free to contact Daniele Alessandrelli at: d.alessandrelli [AT] sssup.it
