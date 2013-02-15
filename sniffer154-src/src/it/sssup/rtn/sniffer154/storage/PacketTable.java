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

import android.database.sqlite.SQLiteDatabase;
import android.provider.BaseColumns;

/**
 * A commodity class for creating and updating the database table containing
 * captured frames
 * 
 * @author Daniele Alessandrelli
 * 
 */
public class PacketTable {
	public static final String TABLE_PACKET = "packet";
	public static final String C_PACKET_ID = BaseColumns._ID;
	public static final String C_PACKET_PAYLOAD = "payload";
	public static final String C_PACKET_DATE = "pdate";
	public static final String C_PACKET_SESSION = "psid";
	public static final String C_PACKET_CRC = "crc";
	public static final String C_PACKET_CRC_OK = "crc_ok";
	public static final String C_PACKET_RSSI = "rssi";
	public static final String C_PACKET_LQI = "lqi";

	// @formatter:off
	// Database creation SQL statement
	private static final String CREATE_TABLE_PACKET = "create table "
			+ TABLE_PACKET + " ("
			+ C_PACKET_ID + " integer primary key, "
			+ C_PACKET_DATE + " integer, " 
			+ C_PACKET_PAYLOAD + " blob, "
			
			+ C_PACKET_CRC + " integer, "
			+ C_PACKET_CRC_OK + " integer NOT NULL, "
			+ C_PACKET_RSSI + " integer DEFAULT 0, "
			+ C_PACKET_LQI + " integer DEFAULT 0, "
			
			+ C_PACKET_SESSION + " integer  NOT NULL, " 
			+ "FOREIGN KEY(" + C_PACKET_SESSION + ") " 
			+ "REFERENCES " + SessionTable.TABLE_SESSION
			+ "(" + SessionTable.C_SESSION_ID + ")" 
			+ " ON DELETE CASCADE" + ")";
	// @formatter:on

	/**
	 * Creates the Packet table
	 * 
	 * @param db
	 *            The database
	 */
	public static void onCreate(SQLiteDatabase db) {
		db.execSQL(CREATE_TABLE_PACKET);
	}

	/**
	 * Updates the Packet table
	 * 
	 * @param db
	 *            The database
	 * @param oldVersion
	 *            The old version of the database
	 * @param newVersion
	 *            The new version of the database
	 */
	public static void onUpgrade(SQLiteDatabase db, int oldVersion,
			int newVersion) {
		if (oldVersion <= 2) {
			db.execSQL("DROP TABLE " + TABLE_PACKET);
			db.execSQL(CREATE_TABLE_PACKET);
		}
	}

}
