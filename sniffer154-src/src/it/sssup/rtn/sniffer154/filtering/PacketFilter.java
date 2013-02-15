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
package it.sssup.rtn.sniffer154.filtering;

import it.sssup.rtn.sniffer154.AppSniffer154;
import it.sssup.rtn.sniffer154.R;
import it.sssup.rtn.sniffer154.dissecting.Packet80215;
import it.sssup.rtn.sniffer154.storage.PacketTable;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import android.content.Context;
import android.content.SharedPreferences;
import android.database.Cursor;
import android.util.Log;

/**
 * The Packet Filter class. It allows to filter frames from a
 * sniffing sessions.
 * 
 * @author Daniele Alessandrelli
 * 
 */
public class PacketFilter {

	private static final String TAG = PacketFilter.class.getSimpleName();

	private List<Integer> mFilterMap;
	private int mLastPos;
	private final long mSessionId;
	private FilterCondition mFilterCond;

	/**
	 * Constructs a new PacketFilter for a specific sniffing session
	 * 
	 * @param context
	 *            The context
	 * @param sessionId
	 *            The session ID
	 */
	public PacketFilter(Context context, long sessionId) {
		mSessionId = sessionId;
		mFilterMap = new ArrayList<Integer>();
		mLastPos = 0;
		setUpFiltering(context);
	}

	/**
	 * Returns the session ID for this PacketFilter
	 * 
	 * @return The session ID
	 */
	public long getSid() {
		return mSessionId;
	}

	/**
	 * Filters a cursor
	 * 
	 * @param cur
	 *            The cursor to be filtered
	 * @return The filtered cursor
	 */
	public Cursor filter(Cursor cur) {
		if (mFilterCond == null || cur == null || cur.getCount() == 0)
			return cur;
		updateFilterMap(cur);
		int[] map = new int[mFilterMap.size()];
		int idx = 0;
		for (int i : mFilterMap) {
			map[idx++] = i;
		}
		return new FilterCursorWrapper(cur, map);
	}

	/**
	 * Updates the filtering map
	 * 
	 * @param cur
	 *            To cursor to filter
	 */
	private void updateFilterMap(Cursor cur) {
		int pos;

		cur.moveToPosition(mLastPos);
		while (cur.isAfterLast() == false) {
			if (keepCurrent(cur)) {
				pos = cur.getPosition();
				mFilterMap.add(pos);
			}
			cur.moveToNext();
		}
		mLastPos = cur.getPosition();
	}

	/**
	 * Checks whether the current row must be kept (i.e., not filtered out) or
	 * not
	 * 
	 * @param cur
	 *            The cursor
	 * @return true if the current row must be kept
	 */
	private boolean keepCurrent(Cursor cur) {
		byte[] bytes;
		Packet80215 pack;
		String addr;
		String raw;
		boolean retv;

		bytes = cur.getBlob(cur.getColumnIndex(PacketTable.C_PACKET_PAYLOAD));
		pack = Packet80215.create(bytes);
		retv = false;
		for (String type : mFilterCond.types) {
			retv = retv || type.equalsIgnoreCase(pack.getType());
		}
		if (!mFilterCond.src.equals("")) {
			addr = Long.toHexString(pack.getSourceAddress()).toLowerCase(Locale.US);
			retv = retv && addr.contains(mFilterCond.src);
		}
		if (!mFilterCond.dst.equals("")) {
			addr = Long.toHexString(pack.getDstAddress()).toLowerCase(Locale.US);
			retv = retv && addr.contains(mFilterCond.dst);
		}
		if (!mFilterCond.raw.equals("")) {
			raw = AppSniffer154.toHexString(pack.getRaw()).toLowerCase(Locale.US);
			retv = retv && raw.contains(mFilterCond.raw);
			Log.d(TAG, "raw = " + raw);
			Log.d(TAG, "raw = " + Arrays.toString(pack.getRaw()));
		}
		return retv;
	}

	/**
	 * Sets up the filtering conditions for this PacketFitler retrieving them
	 * from the SharedPreferences
	 * 
	 * @param context
	 *            The context
	 */
	private void setUpFiltering(Context context) {
		SharedPreferences prefs = context.getSharedPreferences(
				AppSniffer154.PREFS_FILTER, 0);
		String key;
		key = context.getString(R.string.prefsFilterEnableKey);
		if (prefs.getBoolean(key, false) == false)
			return;
		mFilterCond = new FilterCondition();

		// key = context.getString(R.string.prefsFilterTypeKey);
		// mFilterCond.types = prefs.getStringSet(key, new HashSet<String>());

		mFilterCond.types = new HashSet<String>();

		key = context.getString(R.string.prefsFilterTypeAckKey);
		if (prefs.getBoolean(key, false))
			mFilterCond.types.add(key);
		key = context.getString(R.string.prefsFilterTypeBeaconKey);
		if (prefs.getBoolean(key, false))
			mFilterCond.types.add(key);
		key = context.getString(R.string.prefsFilterTypeCommandKey);
		if (prefs.getBoolean(key, false))
			mFilterCond.types.add(key);
		key = context.getString(R.string.prefsFilterTypeDataKey);
		if (prefs.getBoolean(key, false))
			mFilterCond.types.add(key);
		key = context.getString(R.string.prefsFilterTypeUnknownKey);
		if (prefs.getBoolean(key, false))
			mFilterCond.types.add(key);

		key = context.getString(R.string.prefsFilterSrcKey);
		mFilterCond.src = prefs.getString(key, "").toLowerCase(Locale.US);
		Log.d(TAG, "mFilterCond.src = " + mFilterCond.src);

		key = context.getString(R.string.prefsFilterDstKey);
		mFilterCond.dst = prefs.getString(key, "").toLowerCase(Locale.US);
		Log.d(TAG, "mFilterCond.dst = " + mFilterCond.dst);

		key = context.getString(R.string.prefsFilterRawKey);
		mFilterCond.raw = prefs.getString(key, "").toLowerCase(Locale.US);
		Log.d(TAG, "mFilterCond.raw = " + mFilterCond.raw);

	}

	/**
	 * Commodity class for representing filtering conditions
	 * 
	 * @author Daniele Alessandrelli
	 * 
	 */
	private class FilterCondition {
		Set<String> types;
		String src;
		String dst;
		String raw;
	}

}
