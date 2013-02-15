/*
 * Copyright (C) 2012,2013 Scuola Superiore Sant'Anna (http://www.sssup.it) 
 * and Consorzio Nazionale Interuniversitario per le Telecomunicazioni 
 * (http://www.cnit.it).
 * 
 * This file is part of Sniffer 15.4, an IEEE 802.15.4 packet sniffer for 
 * Android devices.
 * 
 * Sniffer 15.4 is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *  
 * Sniffer 15.4 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *  
 * You should have received a copy of the GNU General Public License
 * along with Sniffer 15.4.  If not, see <http://www.gnu.org/licenses/>.
 */
package it.sssup.rtn.sniffer154.dissecting;

import it.sssup.rtn.sniffer154.AppSniffer154;
import it.sssup.rtn.sniffer154.R;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Locale;

import android.content.Context;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.TextView;

class consts {
	static final int UWL_MAC_ADDRESS_NONE = 0x0;
	static final int UWL_MAC_ADDRESS_SHORT = 0x2;
	static final int UWL_MAC_ADDRESS_EXTD = 0x3;
}

public abstract class Packet80215 {
	
	private static final String TAG = Packet80215.class.getSimpleName();

	public enum FrameType {
		BEACON(0x0), DATA(0x01), ACK(0x02), COMMAND(0x03);
		private int code;

		private FrameType(int c) {
			code = c;
		}

		public int getValue() {
			return code;
		}
	}

	private class addressingFields {
		boolean shortSrcAddress = false;
		boolean shortDstAddress = false;
		int panidCompression = 0;
		int dstPanId = -1;
		int srcPanId = -1;
		long srcAddress = -1;
		long dstAddress = -1;
	}


	protected byte[] raw; // TODO: extract (and show) only the payload.
	protected int fcf;
	private int seqNo;
	private int lqi;
	private int rssi;
	private int rxLen;
	protected int fcs;
	protected addressingFields f;

	static public Packet80215 create(byte[] rawData) {
		InputStream is = new ByteArrayInputStream(rawData);
		LittleEndianDataInputStream din = new LittleEndianDataInputStream(is);

		try { // TODO: in the final version of the system the first 3 bytes will
				// be metadata (rssi, lqi, len)
			// packet info, 3 bytes
			// int rxLen = 0xFF & din.readByte();
			// int lqi = 0xFF & din.readByte();
			// int rssi = 0xFF & din.readByte();

			int rxLen = 0;
			int lqi = 0;
			int rssi = 0;

			// packet content starts here..
			int fc = 0xFFFF & din.readUnsignedShort();
			int seqNo = 0xFF & din.readByte();

			int v = (fc & 0x07);

//			Log.d("AZZA", "FC = " + Integer.toHexString(fc));
//			Log.d("AZZA", "v = " + Integer.toHexString(v));
//			Log.d("AZZA", "seqno = " + Integer.toHexString(seqNo));
			if (v == FrameType.BEACON.getValue()) {
				return new BeaconPacket(rawData, din, rxLen, lqi, rssi, fc,
						seqNo);
			} else if (v == FrameType.DATA.getValue()) {
				return new DataPacket(rawData, din, rxLen, lqi, rssi, fc, seqNo);
			} else if (v == FrameType.ACK.getValue()) {
				return new AckPacket(rawData, din, rxLen, lqi, rssi, fc, seqNo);
			} else if (v == FrameType.COMMAND.getValue())
				return new CommandPacket(rawData, din, rxLen, lqi, rssi, fc,
						seqNo);
			else
				return new UnknownPacket(rawData, din, rxLen, lqi, rssi, fc,
						seqNo);
		} catch (IOException e) {
			Log.d(TAG, "rawData.length = " + rawData.length);
			e.printStackTrace();
		}
		return new UnknownPacket(rawData, din, 0, 0, 0, 0, 0);
	}

	/* Protected, we use the static method create to create objects */
	protected Packet80215(byte[] rawdata, LittleEndianDataInputStream din,
			int rxLen2, int lqi2, int rssi2, int fc2, int seqNo2) {
		fcf = fc2;
		lqi = lqi2;
		rssi = rssi2;
		rxLen = rxLen2;
		seqNo = seqNo2;
		f = new addressingFields();
		raw = new byte[rawdata.length];
		System.arraycopy(rawdata, 0, raw, 0, rawdata.length);

	}

	protected void fillAddressingFields(View v) {
		TextView srcPan = (TextView) v.findViewById(R.id.pansrc);

		srcPan.setText((f.srcPanId < 0) ? "-" : "0x"
				+ Integer.toHexString(f.srcPanId).toUpperCase(Locale.US));

		TextView dstPan = (TextView) v.findViewById(R.id.pandst);
		dstPan.setText((f.dstPanId < 0) ? "-" : "0x"
				+ Integer.toHexString(f.dstPanId).toUpperCase(Locale.US));

		TextView srcAddr = (TextView) v.findViewById(R.id.addsrc);
		srcAddr.setText((f.srcAddress < 0) ? "-" : "0x"
				+ Long.toHexString(f.srcAddress).toUpperCase(Locale.US));

		TextView dstAddr = (TextView) v.findViewById(R.id.adddst);
		dstAddr.setText((f.dstAddress < 0) ? "-" : "0x"
				+ Long.toHexString(f.dstAddress).toUpperCase(Locale.US));
	}

	protected void fillRawData(View v) {
		TextView rawdata = (TextView) v.findViewById(R.id.raw);
		rawdata.setText(AppSniffer154.toHexString(getRaw()));
	}

	public abstract View createDetailView(Context context);

	abstract public String getType();

	public int getLqi() {
		return lqi;
	}

	public int getRssi() {
		return rssi;
	}

	public int getRxLen() {
		return rxLen;
	}

	public int getSeqNo() {
		return seqNo;
	}

	public long getDstAddress() {
		return f.dstAddress;
	}

	public long getSourceAddress() {
		return f.srcAddress;
	}

	public int getSrcPanId() {
		return f.srcPanId;
	}

	public int getDstPanId() {
		return f.dstPanId;
	}

	public boolean isSrcShortAddress() {
		return f.shortSrcAddress;
	}

	public boolean isDstShortAddress() {
		return f.shortDstAddress;
	}

	public byte[] getRaw() {
		return raw;
	}

	protected addressingFields getAddressingFields(
			LittleEndianDataInputStream din, int fcf) throws IOException {
		f.panidCompression = ((0xFFFF & fcf) >> 6) & 0x01;

//		Log.d("AZZA", "Panid Compression = " + f.panidCompression);
//		Log.d("AZZA",
//				"fcf = " + Integer.toHexString(((0xFFFF & fcf) >> 6) & 0x01));

		int dstAddressingMode = (((0xFFFF & fcf) >> 10) & 0x03);
		int srcAddressingMode = (((0xFFFF & fcf) >> 14) & 0x03);

		if (dstAddressingMode == consts.UWL_MAC_ADDRESS_SHORT) {
			f.shortDstAddress = true;
			f.dstPanId = 0xFFFF & din.readUnsignedShort();
//			Log.d("AZZA", "SourcePanid = " + Integer.toHexString(f.dstPanId));
			f.dstAddress = 0xFFFF & din.readUnsignedShort();
//			Log.d("AZZA", "SourceAddress = " + Long.toHexString(f.dstAddress));
		} else if (dstAddressingMode == consts.UWL_MAC_ADDRESS_EXTD) {
			f.shortDstAddress = false;
			f.dstPanId = 0xFFFF & din.readUnsignedShort();
			f.dstAddress = din.readLong();
		} else {
			f.dstAddress = -1;
		}

		if (srcAddressingMode == consts.UWL_MAC_ADDRESS_SHORT) {
			f.shortSrcAddress = true;
			if (f.panidCompression == 0) {
				f.srcPanId = 0xFFFF & din.readUnsignedShort();
//				Log.d("AZZA",
//						"SourcePanid = " + Integer.toHexString(f.srcPanId));
			} else {
				f.srcPanId = -1;
			}
			f.srcAddress = 0xFFFF & din.readUnsignedShort();
//			Log.d("AZZA", "SourceAddress = " + Long.toHexString(f.srcAddress));
		} else if (srcAddressingMode == consts.UWL_MAC_ADDRESS_EXTD) {
			f.shortSrcAddress = false;
			if (f.panidCompression == 0) {
				f.srcPanId = 0xFFFF & din.readUnsignedShort();
			} else {
				f.srcPanId = -1;
			}
			f.srcAddress = din.readLong();
		} else {
			f.srcAddress = -1;
		}
		return f;
	}
}

class AckPacket extends Packet80215 {
	public AckPacket(byte[] raw, LittleEndianDataInputStream din, int rxLen,
			int lqi, int rssi, int fc, int seqNo) throws IOException {
		super(raw, din, rxLen, lqi, rssi, fc, seqNo);
		// fcs = 0xFFFF & din.readUnsignedShort();
		// Done
	}

	public String getType() {
		return "ACK";
	}

	@Override
	public View createDetailView(Context context) {
		LayoutInflater vi = LayoutInflater.from(context);
		View v = vi.inflate(R.layout.packet154_ack, null);

		fillRawData(v);
		return v;
	}
}

class BeaconPacket extends Packet80215 {
	private int bo = 0;
	private int so = 0;

	// private int gtsField = 0;
	public BeaconPacket(byte[] raw, LittleEndianDataInputStream din, int rxLen,
			int lqi, int rssi, int fcf, int seqNo) throws IOException {
		super(raw, din, rxLen, lqi, rssi, fcf, seqNo);
		getAddressingFields(din, fcf);

		int beaconInfo = 0xFFFF & din.readUnsignedShort();

		bo = 0x0F & (0xFF & beaconInfo); // ((*(ss)) & 0x0F)
		so = (0xFF & beaconInfo) >> 4; // ((*(ss)) >> 4)

		// gtsField = 0xFF & din.readByte();

//		Log.d("AZZA", "BO = " + Integer.toHexString(bo));
//		Log.d("AZZA", "SO = " + Integer.toHexString(so));

	}

	public String getType() {
		return "BCN";
	}

	public int getBo() {
		return bo;
	}

	public int getSo() {
		return so;
	}

	@Override
	public View createDetailView(Context context) {
		LayoutInflater vi = LayoutInflater.from(context);
		View v = vi.inflate(R.layout.packet154_beacon, null);

		fillAddressingFields(v);

		TextView bo = (TextView) v.findViewById(R.id.bo);
		bo.setText("Beacon Order = " + Integer.toString(getBo()));

		TextView so = (TextView) v.findViewById(R.id.so);
		so.setText("Superframe Order = " + Integer.toString(getSo()));

		fillRawData(v);

		return v;
	}
}

class CommandPacket extends Packet80215 {
	public CommandPacket(byte[] raw, LittleEndianDataInputStream din,
			int rxLen, int lqi, int rssi, int fc, int seqNo) throws IOException {
		super(raw, din, rxLen, lqi, rssi, fc, seqNo);
		getAddressingFields(din, fcf);
	}

	public String getType() {
		return "CMD";
	}

	@Override
	public View createDetailView(Context context) {
		LayoutInflater vi = LayoutInflater.from(context);
		View v = vi.inflate(R.layout.packet154_ctrl, null);

		fillAddressingFields(v);

		TextView ctrl = (TextView) v.findViewById(R.id.ctrl);
		ctrl.setText("Altri campi del pacchetto di controllo");

		fillRawData(v);

		return v;
	}
}

class DataPacket extends Packet80215 {

	public DataPacket(byte[] raw, LittleEndianDataInputStream din, int rxLen,
			int lqi, int rssi, int fc, int seqNo) throws IOException {
		super(raw, din, rxLen, lqi, rssi, fc, seqNo);
		getAddressingFields(din, fcf);
	}

	public String getType() {
		return "DATA";
	}

	@Override
	public View createDetailView(Context context) {
		LayoutInflater vi = LayoutInflater.from(context);
		View v = vi.inflate(R.layout.packet154_simple, null);

		fillAddressingFields(v);

		fillRawData(v);

		return v;
	}
}

class UnknownPacket extends Packet80215 {

	protected UnknownPacket(byte[] rawdata, LittleEndianDataInputStream din,
			int rxLen2, int lqi2, int rssi2, int fc2, int seqNo2) {
		super(rawdata, din, rxLen2, lqi2, rssi2, fc2, seqNo2);
	}

	public String getType() {
		return "UNKNOWN";
	}

	@Override
	public View createDetailView(Context context) {
		LayoutInflater vi = LayoutInflater.from(context);
		View v = vi.inflate(R.layout.packet154_ack, null);

		fillRawData(v);
		return v;
	}
}
