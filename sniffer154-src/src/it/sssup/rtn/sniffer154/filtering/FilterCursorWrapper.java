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

import java.util.Arrays;

import android.database.Cursor;
import android.database.CursorWrapper;

/**
 * A cursor wrapper filtering rows based on a filter map
 * 
 * @author Daniele Alessandrelli
 * 
 */
public class FilterCursorWrapper extends CursorWrapper {

	private int[] mFilterMap;
	private int mPos = -1;

	public FilterCursorWrapper(Cursor cursor, int[] filterMap) {
		super(cursor);
		this.mFilterMap = Arrays.copyOf(filterMap, filterMap.length);
	}

//	private void addIndex(int id) {
//		int[] tmp = new int[mFilterMap.length + 1];
//		tmp[mFilterMap.length + 1] = id;
//		mFilterMap = tmp;
//	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see android.database.CursorWrapper#getCount()
	 */
	@Override
	public int getCount() {
		return mFilterMap.length;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see android.database.CursorWrapper#moveToPosition(int)
	 */
	@Override
	public boolean moveToPosition(int pos) {
		if (pos >= mFilterMap.length)
			return false;
		boolean moved = super.moveToPosition(mFilterMap[pos]);
		if (moved)
			mPos = pos;
		return moved;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see android.database.CursorWrapper#move(int)
	 */
	@Override
	public final boolean move(int offset) {
		return moveToPosition(mPos + offset);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see android.database.CursorWrapper#moveToFirst()
	 */
	@Override
	public final boolean moveToFirst() {
		return moveToPosition(0);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see android.database.CursorWrapper#moveToLast()
	 */
	@Override
	public final boolean moveToLast() {
		return moveToPosition(getCount() - 1);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see android.database.CursorWrapper#moveToNext()
	 */
	@Override
	public final boolean moveToNext() {
		return moveToPosition(mPos + 1);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see android.database.CursorWrapper#moveToPrevious()
	 */
	@Override
	public final boolean moveToPrevious() {
		return moveToPosition(mPos - 1);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see android.database.CursorWrapper#isFirst()
	 */
	@Override
	public final boolean isFirst() {
		return mPos == 0 && getCount() != 0;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see android.database.CursorWrapper#isLast()
	 */
	@Override
	public final boolean isLast() {
		int cnt = getCount();
		return mPos == (cnt - 1) && cnt != 0;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see android.database.CursorWrapper#isBeforeFirst()
	 */
	@Override
	public final boolean isBeforeFirst() {
		if (getCount() == 0) {
			return true;
		}
		return mPos == -1;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see android.database.CursorWrapper#isAfterLast()
	 */
	@Override
	public final boolean isAfterLast() {
		if (getCount() == 0) {
			return true;
		}
		return mPos == getCount();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see android.database.CursorWrapper#getPosition()
	 */
	@Override
	public int getPosition() {
		return mPos;
	}
}
