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
package it.sssup.rtn.sniffer154.storage;

import it.sssup.rtn.sniffer154.AppSniffer154;
import it.sssup.rtn.sniffer154.filtering.PacketFilter;

import java.util.List;

import android.content.ContentProvider;
import android.content.ContentResolver;
import android.content.ContentUris;
import android.content.ContentValues;
import android.content.SharedPreferences;
import android.content.SharedPreferences.OnSharedPreferenceChangeListener;
import android.content.UriMatcher;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteQueryBuilder;
import android.net.Uri;
import android.text.TextUtils;

/**
 * A content provider for storing and accessing captured frames
 * 
 * @author Daniele Alessandrelli
 * 
 */
public class PacketContentProvider extends ContentProvider implements
		OnSharedPreferenceChangeListener {

	@SuppressWarnings("unused")
	private static String TAG = PacketContentProvider.class.getSimpleName();

	// mDbHelper
	private PacketDatabaseHelper mDbHelper;

	private PacketFilter filter;

	// Used for the UriMacher
	private static final int SESSION_PACKETS = 1;
	private static final int SESSION_PACKETS_ID = 2;
	private static final int SESSIONS = 3;
	private static final int SESSIONS_ID = 4;
	private static final int PACKETS_ID = 5;
	private static final int FILTERED_SESSION_PACKETS = 6;

	public static final String AUTHORITY = "it.retis.rtn.sniffer154.contentprovider";

	public static final String BASE_PATH_PACKETS = "packets";
	public static final String BASE_PATH_SESSIONS = "sessions";
	public static final String BASE_PATH_FILTERED = "filtered";

	public static final String CONTENT_TYPE_MULTIPLE_PACKETS = ContentResolver.CURSOR_DIR_BASE_TYPE
			+ "/" + "vnd.sssup.rtn.sniffer154.packets";
	public static final String CONTENT_TYPE_SINGLE_PACKET = ContentResolver.CURSOR_ITEM_BASE_TYPE
			+ "/" + "vnd.sssup.rtn.sniffer154.packet";
	public static final String CONTENT_TYPE_MULTIPLE_SESSIONS = ContentResolver.CURSOR_DIR_BASE_TYPE
			+ "/" + "vnd.sssup.rtn.sniffer154.sessions";
	public static final String CONTENT_TYPE_SINGLE_SESSION = ContentResolver.CURSOR_ITEM_BASE_TYPE
			+ "/" + "vnd.sssup.rtn.sniffer154.session";

	public static final Uri SESSIONS_URI = Uri.parse("content://" + AUTHORITY
			+ "/" + BASE_PATH_SESSIONS);
	public static final Uri PACKETS_URI = Uri.parse("content://" + AUTHORITY
			+ "/" + BASE_PATH_PACKETS);

	private static final UriMatcher sURIMatcher = new UriMatcher(
			UriMatcher.NO_MATCH);

	static {
		// e.g., it.retis.rtn.sniffer154.contentprovider/sessions
		sURIMatcher.addURI(AUTHORITY, BASE_PATH_SESSIONS, SESSIONS);
		// e.g., it.retis.rtn.sniffer154.contentprovider/sessions/23
		sURIMatcher.addURI(AUTHORITY, BASE_PATH_SESSIONS + "/#", SESSIONS_ID);
		// e.g., it.retis.rtn.sniffer154.contentprovider/sessions/23/packets
		sURIMatcher.addURI(AUTHORITY, BASE_PATH_SESSIONS + "/#/"
				+ BASE_PATH_PACKETS, SESSION_PACKETS);
		// e.g.,
		// it.retis.rtn.sniffer154.contentprovider/sessions/23/packets/filtered
		sURIMatcher.addURI(AUTHORITY, BASE_PATH_SESSIONS + "/#/"
				+ BASE_PATH_PACKETS + "/" + BASE_PATH_FILTERED,
				FILTERED_SESSION_PACKETS);
		// e.g., it.retis.rtn.sniffer154.contentprovider/sessions/23/packets/13
		sURIMatcher.addURI(AUTHORITY, BASE_PATH_SESSIONS + "/#/"
				+ BASE_PATH_PACKETS + "/#", SESSION_PACKETS_ID);
		// e.g., it.retis.rtn.sniffer154.contentprovider/packets/13
		sURIMatcher.addURI(AUTHORITY, BASE_PATH_PACKETS + "/#/", PACKETS_ID);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see android.content.ContentProvider#onCreate()
	 */
	@Override
	public boolean onCreate() {
		mDbHelper = new PacketDatabaseHelper(getContext());
		getContext().getSharedPreferences(AppSniffer154.PREFS_FILTER, 0)
				.registerOnSharedPreferenceChangeListener(this);
		return true;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see android.content.ContentProvider#getType(android.net.Uri)
	 */
	@Override
	public String getType(Uri uri) {
		int match = sURIMatcher.match(uri);
		switch (match) {
		case SESSIONS:
			return CONTENT_TYPE_MULTIPLE_SESSIONS;
		case SESSIONS_ID:
			return CONTENT_TYPE_SINGLE_SESSION;
		case SESSION_PACKETS:
			return CONTENT_TYPE_MULTIPLE_PACKETS;
		case SESSION_PACKETS_ID:
			return CONTENT_TYPE_SINGLE_PACKET;
		default:
			return null;
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see android.content.ContentProvider#query(android.net.Uri,
	 * java.lang.String[], java.lang.String, java.lang.String[],
	 * java.lang.String)
	 */
	@Override
	public synchronized Cursor query(Uri uri, String[] projection,
			String selection, String[] selectionArgs, String sortOrder) {
		int match;
		SQLiteQueryBuilder queryBuilder;
		Cursor cursor;
		long sid;
		SQLiteDatabase db;
		
		db = mDbHelper.getReadableDatabase();
		match = sURIMatcher.match(uri);
		queryBuilder = new SQLiteQueryBuilder();
		cursor = null;
		sid = -1;
		switch (match) {
		case SESSIONS:
			queryBuilder.setTables(SessionTable.TABLE_SESSION);
			break;
		case FILTERED_SESSION_PACKETS:
		case SESSION_PACKETS:
			queryBuilder.setTables(PacketTable.TABLE_PACKET);
			List<String> segments = uri.getPathSegments();
			sid = Long.parseLong(segments.get(1));
			queryBuilder.appendWhere(PacketTable.C_PACKET_SESSION + "=" + sid);
			break;
		case SESSION_PACKETS_ID:
			queryBuilder.setTables(PacketTable.TABLE_PACKET);
			long pid = ContentUris.parseId(uri);
			queryBuilder.appendWhere(PacketTable.C_PACKET_ID + "=" + pid);
			break;
		case PACKETS_ID:
			queryBuilder.setTables(PacketTable.TABLE_PACKET);
			long id = ContentUris.parseId(uri);
			queryBuilder.appendWhere(PacketTable.C_PACKET_ID + "=" + id);
			break;
		case SESSIONS_ID:
			queryBuilder.setTables(SessionTable.TABLE_SESSION);
			sid = ContentUris.parseId(uri);
			queryBuilder.appendWhere(SessionTable.C_SESSION_ID + "=" + sid);
			break;
		default:
			throw new IllegalArgumentException("Unknown URI: " + uri);
		}
		//Log.d(TAG, uri.toString());
		//Log.d(TAG, queryBuilder.buildQuery(projection, selection,
		//		selectionArgs, null, null, sortOrder, null));
		cursor = queryBuilder.query(db, projection, selection, selectionArgs,
				null, null, sortOrder);
		if (match == FILTERED_SESSION_PACKETS) {
			PacketFilter filter = getPacketFilter(sid);
			cursor = filter.filter(cursor);
		}
		// Make sure that potential listeners are getting notified
		cursor.setNotificationUri(getContext().getContentResolver(), uri);
		return cursor;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see android.content.ContentProvider#insert(android.net.Uri,
	 * android.content.ContentValues)
	 */
	@Override
	public synchronized Uri insert(Uri uri, ContentValues values) {
		//Log.d(TAG, "inserting uri " + uri.toString());
		int match = sURIMatcher.match(uri);
		//Log.d(TAG, "matching " + match);
		SQLiteDatabase db = mDbHelper.getWritableDatabase();
		long id = -1;
		switch (match) {
		case SESSIONS:
			id = db.insert(SessionTable.TABLE_SESSION, null, values);
			break;
		case SESSION_PACKETS:
			List<String> segments = uri.getPathSegments();
			long sid = Long.parseLong(segments.get(1));
			values.put(PacketTable.C_PACKET_SESSION, sid);
			id = db.insert(PacketTable.TABLE_PACKET, null, values);
			break;
		default:
			throw new IllegalArgumentException("Unknown URI: " + uri);
		}
		getContext().getContentResolver().notifyChange(uri, null);
		return ContentUris.withAppendedId(uri, id);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see android.content.ContentProvider#delete(android.net.Uri,
	 * java.lang.String, java.lang.String[])
	 */
	@Override
	public int delete(Uri uri, String selection, String[] selectionArgs) {
		int match = sURIMatcher.match(uri);
		int retv;
		SQLiteDatabase db = mDbHelper.getWritableDatabase();
		switch (match) {
		case SESSIONS_ID:
			long id = ContentUris.parseId(uri);
			String sel = SessionTable.C_SESSION_ID + "=" + id;
			if (!TextUtils.isEmpty(selection)) {
				sel += " and " + selection;
			}
			retv = db.delete(SessionTable.TABLE_SESSION, sel, selectionArgs);
			uri = SESSIONS_URI;
			break;
		default:
			throw new IllegalArgumentException("Unknown URI: " + uri);
		}
		getContext().getContentResolver().notifyChange(uri, null);
		return retv;

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see android.content.ContentProvider#update(android.net.Uri,
	 * android.content.ContentValues, java.lang.String, java.lang.String[])
	 */
	@Override
	public int update(Uri uri, ContentValues values, String selection,
			String[] selectionArgs) {
		throw new IllegalArgumentException("Unknown URI: " + uri);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see android.content.SharedPreferences.OnSharedPreferenceChangeListener#
	 * onSharedPreferenceChanged(android.content.SharedPreferences,
	 * java.lang.String)
	 */
	@Override
	public void onSharedPreferenceChanged(SharedPreferences sharedPreferences,
			String key) {
		getContext().getContentResolver().notifyChange(SESSIONS_URI, null);
		filter = null;
	}

	/**
	 * Returns a packet filter for a specific session
	 * 
	 * @param sid
	 *            The session ID
	 * @return The Packet filter of the specified session
	 */
	private PacketFilter getPacketFilter(long sid) {
		if (filter != null && filter.getSid() == sid)
			return filter;
		filter = new PacketFilter(getContext(), sid);
		return filter;
	}

}
