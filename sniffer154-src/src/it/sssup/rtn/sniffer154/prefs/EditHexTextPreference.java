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
package it.sssup.rtn.sniffer154.prefs;

import android.content.Context;
import android.preference.EditTextPreference;
import android.text.InputFilter;
import android.text.Spanned;
import android.util.AttributeSet;
import android.view.View;

/**
 * An EditTextPreference which accepts only hex inputs
 * 
 * @author Daniele Alessandrelli
 * 
 */
public class EditHexTextPreference extends EditTextPreference {

	@SuppressWarnings("unused")
	private static final String TAG = EditTextPreference.class.getSimpleName();

	/**
	 * The constructor
	 * 
	 * @param context
	 *            The context
	 * @param attrs
	 *            The attribute set
	 * 
	 * @see android.preference.EditTextPreference#EditTextPreference(Context,
	 *      AttributeSet)
	 */
	public EditHexTextPreference(Context context, AttributeSet attrs) {
		super(context, attrs);
	}

	/**
	 * The constructor
	 * 
	 * @param context
	 * 
	 * @see android.preference.EditTextPreference#EditTextPreference(Context)
	 */
	public EditHexTextPreference(Context context) {
		super(context);
	}

	/**
	 * The constructor
	 * 
	 * @param context
	 * @param attrs
	 * @param defStyle
	 * 
	 * @see android.preference.EditTextPreference#EditTextPreference(Context,
	 *      AttributeSet, int)
	 */
	public EditHexTextPreference(Context context, AttributeSet attrs,
			int defStyle) {
		super(context, attrs, defStyle);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see android.preference.DialogPreference#onCreateDialogView()
	 */
	@Override
	protected View onCreateDialogView() {
		View view;
		
		view = super.onCreateDialogView();
		getEditText().setFilters(new InputFilter[] { new HexInputFilter() });
		
		return view;
	}

	/**
	 * An InputFilter which constrains the input to hex digit
	 * 
	 * @author Daniele Alessandrelli
	 * 
	 */
	class HexInputFilter implements InputFilter {

		@Override
		public CharSequence filter(CharSequence source, int start, int end,
				Spanned dest, int dstart, int dend) {
			for (int i = start; i < end; i++) {
				char c = source.charAt(i);
				if (!Character.isDigit(c)) {
					c = Character.toLowerCase(c);
					if (c < 'a' || c > 'f')
						return "";
				}
			}
			return null;
		}
	}
}
