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

import it.sssup.rtn.sniffer154.R;
import android.content.Context;
import android.preference.DialogPreference;
import android.util.AttributeSet;
import android.view.View;
import android.widget.NumberPicker;

/**
 * A ChannelPickerPreference which allows the user to input numeric values
 * 
 * @author Daniele Alessandrelli
 * 
 */
public class ChannelPickerPreference extends DialogPreference {

	@SuppressWarnings("unused")
	private static final String TAG = ChannelPickerPreference.class
			.getSimpleName();

	private NumberPicker mNumberPicker;

	/**
	 * The constructor
	 * 
	 * @param context
	 *            The context
	 * @param attrs
	 *            The attribute set
	 * 
	 * @see android.preference.DialogPreference#EditTextPreference(Context,
	 *      AttributeSet)
	 */
	public ChannelPickerPreference(Context context, AttributeSet attrs) {
		super(context, attrs);
		// attrs.get
		// setPersistent(false);
		setDialogLayoutResource(R.layout.channel_picker);
	}

	@Override
	protected void onBindDialogView(View view) {
		super.onBindDialogView(view);
		mNumberPicker = (NumberPicker) view.findViewById(R.id.numberPicker);
		mNumberPicker.setMaxValue(26);
		mNumberPicker.setMinValue(11);
		mNumberPicker.setValue(getPersistedInt(11));
		mNumberPicker.setWrapSelectorWheel(false);
	}

	@Override
	protected void onDialogClosed(boolean positiveResult) {
		if (positiveResult) {
			persistInt(mNumberPicker.getValue());
		}
		super.onDialogClosed(positiveResult);
	}

}
