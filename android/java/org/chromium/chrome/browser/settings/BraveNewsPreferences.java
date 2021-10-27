
/* Copyright (c) 2021 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.chromium.chrome.browser.settings;

import android.content.SharedPreferences;
import android.os.Bundle;
import android.view.KeyEvent;
import android.view.inputmethod.EditorInfo;
import android.widget.EditText;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.preference.CheckBoxPreference;
import androidx.preference.EditTextPreference;
import androidx.preference.Preference;
import androidx.preference.PreferenceCategory;
import androidx.preference.PreferenceFragmentCompat;
import androidx.preference.PreferenceManager;
import androidx.preference.PreferenceScreen;
import androidx.preference.SwitchPreference;

import org.chromium.base.ContextUtils;
import org.chromium.base.Log;
import org.chromium.chrome.R;
import org.chromium.chrome.browser.BraveLaunchIntentDispatcher;
import org.chromium.chrome.browser.preferences.BravePreferenceKeys;
import org.chromium.chrome.browser.settings.BraveAddNewsSources;
import org.chromium.chrome.browser.settings.BravePreferenceFragment;
import org.chromium.components.browser_ui.settings.ChromeBasePreference;
import org.chromium.components.browser_ui.settings.ChromeSwitchPreference;
import org.chromium.chrome.browser.settings.SearchPreference;
import org.chromium.components.browser_ui.settings.SettingsUtils;
import android.widget.Button;

import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;

import org.chromium.brave_news.mojom.Publisher;
import org.chromium.brave_news.mojom.BraveNewsController;
import org.chromium.chrome.browser.brave_news.BraveNewsControllerFactory;
import org.chromium.mojo.bindings.ConnectionErrorHandler;
import org.chromium.mojo.system.MojoException;
import org.chromium.chrome.browser.preferences.BravePrefServiceBridge;

import java.util.Map;

import java.util.HashMap;

import java.util.TreeMap;
import java.util.ArrayList;
import java.util.List;

public class BraveNewsPreferences
        extends BravePreferenceFragment implements Preference.OnPreferenceChangeListener,
        ConnectionErrorHandler {
    public static final String PREF_TURN_ON_NEWS = "kBraveTodayOptedIn";
    public static final String PREF_SHOW_NEWS = "kNewTabPageShowToday";
    public static final String PREF_SHOW_OPTIN = "show_optin";
    public static final String PREF_SOURCES_SECTION = "your_sources_section";
    public static final String PREF_ADD_SOURCES = "add_source_news";

    private ChromeSwitchPreference turnOnNews;
    private ChromeSwitchPreference showNews;
    private PreferenceCategory yourSources;
    private EditText mEditText;
    private PreferenceScreen mainScreen;
    private PreferenceManager preferenceManager;
    private TreeMap <String, List<Publisher>> categsPublishers;

    private final HashMap<String, Preference> mRemovedPreferences = new HashMap<>();
    private BraveNewsController mBraveNewsController; 
    private PreferenceFragmentCompat settingsFragment;

    public static int getPreferenceSummary() {
        return BraveLaunchIntentDispatcher.useCustomTabs() ? R.string.text_on : R.string.text_off;
    }

    @Override
    public void onCreatePreferences(@Nullable Bundle savedInstanceState, String rootKey) {

        Log.d("bn", "getfeedprefs onCreatePreferences");
        SettingsUtils.addPreferencesFromResource(this, R.xml.brave_news_preferences);
        InitBraveNewsController();
        turnOnNews = (ChromeSwitchPreference) findPreference(PREF_TURN_ON_NEWS);
        showNews = (ChromeSwitchPreference) findPreference(PREF_SHOW_NEWS);
        settingsFragment = this;

        turnOnNews.setOnPreferenceChangeListener(this);
        showNews.setOnPreferenceChangeListener(this);

        categsPublishers = new TreeMap<>();
        mBraveNewsController.getPublishers((publishers) -> {
            List<Publisher> allPublishers = new ArrayList<>();
            List<Publisher> categoryPublishers = new ArrayList<>();
            for (Map.Entry<String,Publisher> entry : publishers.entrySet()) {
                String key = entry.getKey();
                Publisher publisher = entry.getValue();
                // categsPublishers.computeIfAbsent(publisher.categoryName, k ->new ArrayList<>()).add(publisher);
                categoryPublishers.add(publisher);
                categsPublishers.put(publisher.categoryName, categoryPublishers);
            }
            categsPublishers.put("All Sources", allPublishers);
            addCategs(categsPublishers);
        });
    }


    private void addCategs(TreeMap <String, List<Publisher>> publisherCategories){

        for(Map.Entry<String,List<Publisher>> map : publisherCategories.entrySet()){
            String category = map.getKey();
            List<Publisher> publishers = map.getValue();

            ChromeBasePreference source = new ChromeBasePreference(ContextUtils.getApplicationContext());
            source.setTitle(category);
            source.setKey(category);
            Bundle prefExtras = source.getExtras();
            prefExtras.putString("category", category);
            source.setFragment("org.chromium.chrome.browser.settings.BraveNewsCategorySources");
            mainScreen.addPreference(source);
        }
    }

    @Override
    public void onConnectionError(MojoException e) {
        mBraveNewsController = null;
        InitBraveNewsController();
    }

    private void InitBraveNewsController() {
        if (mBraveNewsController != null) {
            return;
        }

        mBraveNewsController =
                BraveNewsControllerFactory.getInstance().getBraveNewsController(this);
    }

    @Override
    public void onCreate(Bundle savedInstanceState) {

        super.onCreate(savedInstanceState);
        Log.d("bn", "getfeedprefs onCreate");
        getActivity().setTitle(R.string.brave_news_title);

        preferenceManager = getPreferenceManager();
        mainScreen = preferenceManager.getPreferenceScreen();

        boolean isNewsOn =  BravePrefServiceBridge.getInstance().getNewsOptIn();

        if (!isNewsOn) {
            turnOnNews.setChecked(false);
            showNews.setVisible(false);
        } else {
            turnOnNews.setChecked(true);
            turnOnNews.setVisible(false);
            showNews.setVisible(true);
            if ( BravePrefServiceBridge.getInstance().getShowNews()) {
                showNews.setChecked(true);
            } else {
                showNews.setChecked(false);
            }
        }
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
         Log.d("bn", "prefclose in bravenews");
        if (item.getItemId() == R.id.close_menu_id) {
                        Log.d("bn", "prefclose in menu bravenews");

            // Intent intent = new Intent(this, ChromeTabbedActivity.class);
            // intent.addFlags(Intent.FLAG_ACTIVITY_REORDER_TO_FRONT);
            // startActivity(intent);
            
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    @Override
    public boolean onPreferenceChange(Preference preference, Object newValue) {
        String key = preference.getKey();
        Log.d("BN", "pref change key:" + key);
        if (PREF_TURN_ON_NEWS.equals(key)) {
            BravePrefServiceBridge.getInstance().setNewsOptIn((boolean) newValue);
            if ((boolean) newValue) {
                Log.d("BN", "pref true add stuff");
                showNews.setVisible(true);
                showNews.setChecked(true);
                BravePrefServiceBridge.getInstance().setShowNews(true);
            } else {
                showNews.setVisible(false);
            }
        } else if (PREF_SHOW_NEWS.equals(key)) {
            BravePrefServiceBridge.getInstance().setShowNews( (boolean) newValue);
        } 
        return true;
    }

    private void removePreferenceIfPresent(String key) {
        Preference preference = getPreferenceScreen().findPreference(key);
        if (preference != null) {
            getPreferenceScreen().removePreference(preference);
            mRemovedPreferences.put(preference.getKey(), preference);
        }
    }

    /**
     *  We need to override it to avoid NullPointerException in Chromium's child classes
     */
    @Override
    public <T extends Preference> T findPreference(CharSequence key) {
        T result = super.findPreference(key);
        if (result == null) {
            result = (T) mRemovedPreferences.get((String) key);
        }
        return result;
    }
}
