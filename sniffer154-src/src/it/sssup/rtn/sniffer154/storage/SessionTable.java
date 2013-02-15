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
 * sniffing sessions
 * 
 * @author Daniele Alessandrelli
 * 
 */
public class SessionTable {
	static final String TABLE_SESSION = "session";
	public static final String C_SESSION_ID = BaseColumns._ID;
	public static final String C_SESSION_DATE = "sdate";

	// @formatter:off
	// Database creation SQL statement
		private static final String CREATE_TABLE_SESSION = "create table "
				+ TABLE_SESSION 
				+ "(" 
				+ C_SESSION_ID + " integer primary key, " 
				+ C_SESSION_DATE + " integer" 
				+ ")";
		// @formatter:on

	/**
	 * Creates the Session table
	 * 
	 * @param db
	 *            The database
	 */
	public static void onCreate(SQLiteDatabase db) {
		db.execSQL(CREATE_TABLE_SESSION);
	}

	/**
	 * Updates the Session table
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
			db.execSQL("DROP TABLE " + TABLE_SESSION);
			db.execSQL(CREATE_TABLE_SESSION);
		}
	}
}
