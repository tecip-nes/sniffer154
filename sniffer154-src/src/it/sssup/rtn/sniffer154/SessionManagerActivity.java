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
package it.sssup.rtn.sniffer154;

import it.sssup.rtn.sniffer154.storage.PacketContentProvider;
import it.sssup.rtn.sniffer154.storage.SessionTable;
import android.app.Activity;
import android.app.AlertDialog;
import android.app.LoaderManager.LoaderCallbacks;
import android.content.ContentUris;
import android.content.CursorLoader;
import android.content.DialogInterface;
import android.content.Loader;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.text.format.DateUtils;
import android.util.Log;
import android.view.ContextMenu;
import android.view.MenuItem;
import android.view.View;
import android.view.ContextMenu.ContextMenuInfo;
import android.widget.AdapterView;
import android.widget.AdapterView.AdapterContextMenuInfo;
import android.widget.AdapterView.OnItemClickListener;
import android.widget.CursorAdapter;
import android.widget.ListView;
import android.widget.SimpleCursorAdapter;
import android.widget.SimpleCursorAdapter.ViewBinder;
import android.widget.TextView;

/**
 * The activity for managing the sniffing sessions stored in the Android device.
 * The activity shows the list of stored sessions, and allows to load, delete or
 * export them.
 * 
 * @author Daniele Alessandrelli
 * 
 */
public class SessionManagerActivity extends Activity {

	private final static String[] FROM = { SessionTable.C_SESSION_ID,
			SessionTable.C_SESSION_DATE };
	private final static int[] TO = { R.id.textId, R.id.textDate };
	private static final String TAG = SessionManagerActivity.class
			.getSimpleName();
	public static final int LOAD = 1;

	private ListView mListViewSessions;
	private SimpleCursorAdapter mAdapter;
	private long mSessionId;

	/*
	 * (non-Javadoc)
	 * 
	 * @see android.support.v4.app.FragmentActivity#onCreate(android.os.Bundle)
	 */
	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.session_manager_activity);
		mListViewSessions = (ListView) findViewById(R.id.listViewSessions);
		getLoaderManager().initLoader(0, null,
				new SessionLoaderCallbacks());
		mAdapter = new SimpleCursorAdapter(this, R.layout.session_list_row,
				null, FROM, TO, CursorAdapter.FLAG_REGISTER_CONTENT_OBSERVER);
		mAdapter.setViewBinder(new SessionViewBinder());
		mListViewSessions.setAdapter(mAdapter);
		mListViewSessions
				.setOnItemClickListener(new SessionOnItemClickListener());
		registerForContextMenu(mListViewSessions);
	}

	/**
	 * A ViewBinder for a session row
	 * 
	 * @author Daniele Alessandrelli
	 * 
	 */
	private class SessionViewBinder implements ViewBinder {

		/*
		 * (non-Javadoc)
		 * 
		 * @see
		 * android.support.v4.widget.SimpleCursorAdapter.ViewBinder#setViewValue
		 * (android.view.View, android.database.Cursor, int)
		 */
		@Override
		public boolean setViewValue(View view, Cursor cursor, int columnIndex) {
			switch (view.getId()) {
			case R.id.textDate:
				Long time = cursor.getLong(columnIndex);
				CharSequence cs = DateUtils
						.getRelativeDateTimeString(SessionManagerActivity.this,
								time, DateUtils.MINUTE_IN_MILLIS,
								DateUtils.WEEK_IN_MILLIS, 0);
				((TextView) view).setText(cs);
				return true;
			default:
				return false;
			}
		}

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see android.app.Activity#onCreateContextMenu(android.view.ContextMenu,
	 * android.view.View, android.view.ContextMenu.ContextMenuInfo)
	 */
	@Override
	public void onCreateContextMenu(ContextMenu menu, View v,
			ContextMenuInfo menuInfo) {
		getMenuInflater().inflate(R.menu.session_man_cont_menuu, menu);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see android.app.Activity#onContextItemSelected(android.view.MenuItem)
	 */
	@Override
	public boolean onContextItemSelected(MenuItem item) {
		AdapterContextMenuInfo info = (AdapterContextMenuInfo) item
				.getMenuInfo();
		switch (item.getItemId()) {
		case R.id.itemLoad:
			loadSession(info.id);
			return true;
		case R.id.itemDelete:
			deleteSession(info.id);
			return true;
//		case R.id.itemExport:
//			exportSession(info.id);
//			return true;
		default:
			return false;
		}
	}

	/**
	 * Loads the session whose ID is passed as an argument
	 * 
	 * @param id
	 *            The ID of the session to be loaded
	 */
	private void loadSession(long id) {
		AppSniffer154 app;
		Uri sessionUri;

		app = (AppSniffer154) getApplication();
		sessionUri = ContentUris.withAppendedId(
				PacketContentProvider.SESSIONS_URI, id);
		app.setSessionUri(sessionUri);
		setResult(LOAD);
		finish();
	}

//	private void exportSession(long id) {
//		
//
//	}

	/**
	 * Shows a dialog asking for permission to delete the session whose ID is
	 * passed as an argument
	 * 
	 * @param id
	 *            The session ID
	 */
	private void deleteSession(long id) {
		DialogInterface.OnClickListener dialogClickListener;
		AlertDialog.Builder builder;

		mSessionId = id;
		dialogClickListener = new DeleteDialogListener();
		builder = new AlertDialog.Builder(this);
		builder.setMessage(R.string.dialogDeleteMessage)
				.setPositiveButton(android.R.string.yes, dialogClickListener)
				.setNegativeButton(android.R.string.no, dialogClickListener)
				.setTitle(R.string.dialogDeleteTitle).show();
	}

	/**
	 * A DialogInterface.OnClickListener to be used with a dialog asking for
	 * permission to delete a session
	 * 
	 * @author Daniele Alessandrelli
	 * 
	 */
	private class DeleteDialogListener implements
			DialogInterface.OnClickListener {
		@Override
		public void onClick(DialogInterface dialog, int which) {
			switch (which) {
			case DialogInterface.BUTTON_POSITIVE:
				AppSniffer154 app = (AppSniffer154) getApplication();
				app.deleteSession(mSessionId);
				break;
			case DialogInterface.BUTTON_NEGATIVE:
				break;
			}
		}
	};

	/**
	 * An OnItemClickListener which displays the context menu for the row of an
	 * AdapterView
	 * 
	 * @author Daniele Alessandrelli
	 * 
	 */
	private class SessionOnItemClickListener implements OnItemClickListener {

		/*
		 * (non-Javadoc)
		 * 
		 * @see
		 * android.widget.AdapterView.OnItemClickListener#onItemClick(android
		 * .widget.AdapterView, android.view.View, int, long)
		 */
		@Override
		public void onItemClick(AdapterView<?> parent, View view, int position,
				long id) {
			parent.showContextMenuForChild(view);
		}

	}

	/**
	 * The LoaderCallbacks class for the cursor loader used for loading sessions
	 * from the database
	 * 
	 * @author Daniele Alessandrelli
	 * 
	 */
	private class SessionLoaderCallbacks implements LoaderCallbacks<Cursor> {

		/*
		 * (non-Javadoc)
		 * 
		 * @see
		 * android.support.v4.app.LoaderManager.LoaderCallbacks#onCreateLoader
		 * (int, android.os.Bundle)
		 */
		@Override
		public Loader<Cursor> onCreateLoader(int id, Bundle args) {
			Uri uri = PacketContentProvider.SESSIONS_URI;
			CursorLoader cursorLoader = new CursorLoader(
					SessionManagerActivity.this, uri, null, null, null,
					SessionTable.C_SESSION_DATE + " DESC");
			Log.d(TAG, "onCreateLoader()");
			return cursorLoader;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see
		 * android.support.v4.app.LoaderManager.LoaderCallbacks#onLoadFinished
		 * (android.support.v4.content.Loader, java.lang.Object)
		 */
		@Override
		public void onLoadFinished(Loader<Cursor> loader, Cursor cursor) {
			Log.d(TAG, "onLoadFinished()");
			mAdapter.swapCursor(cursor);
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see
		 * android.support.v4.app.LoaderManager.LoaderCallbacks#onLoaderReset
		 * (android.support.v4.content.Loader)
		 */
		@Override
		public void onLoaderReset(Loader<Cursor> cursor) {
			Log.d(TAG, "onLoaderReset()");
			mAdapter.swapCursor(null);
		}
	}

}
