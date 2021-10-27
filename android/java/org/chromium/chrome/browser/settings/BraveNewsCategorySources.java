/* Copyright (c) 2021 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.chromium.chrome.browser.settings;

import android.os.Bundle;

import androidx.preference.Preference;
import androidx.preference.PreferenceFragmentCompat;
import androidx.preference.PreferenceManager;
import androidx.preference.PreferenceScreen;
import androidx.preference.SwitchPreference;
import org.chromium.chrome.browser.settings.SearchPreference;
import org.chromium.chrome.browser.preferences.SharedPreferencesManager;
import org.chromium.chrome.browser.preferences.BravePreferenceKeys;
import android.content.SharedPreferences;

import org.chromium.base.ContextUtils;
import org.chromium.base.Log;
import org.chromium.brave_news.mojom.Publisher;
import org.chromium.brave_news.mojom.UserEnabled;
import org.chromium.brave_news.mojom.BraveNewsController;
import org.chromium.chrome.browser.brave_news.BraveNewsControllerFactory;
import org.chromium.components.browser_ui.settings.ChromeSwitchPreference;
import androidx.preference.SwitchPreferenceCompat;
import org.chromium.mojo.bindings.ConnectionErrorHandler;
import org.chromium.mojo.system.MojoException;
import java.util.Map;

import java.util.TreeMap;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;

import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;

import org.chromium.chrome.R;

public class BraveNewsCategorySources extends PreferenceFragmentCompat implements 
    ConnectionErrorHandler  {

    private PreferenceManager preferenceManager;
    private BraveNewsController mBraveNewsController;
    private String categoryArg;

    private TreeMap <String, List<Publisher>> categsPublishers;

	@Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Bundle args = getArguments();
        categoryArg = args.getString("category");
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
         Log.d("bn", "prefclose in BraveNewsCategorySources");
        if (item.getItemId() == R.id.close_menu_id) {
                        Log.d("bn", "prefclose in menu BraveNewsCategorySources");

            // Intent intent = new Intent(this, ChromeTabbedActivity.class);
            // intent.addFlags(Intent.FLAG_ACTIVITY_REORDER_TO_FRONT);
            // startActivity(intent);
            
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    @Override
    public void onCreatePreferences(Bundle savedInstanceState, String rootKey) {
        InitBraveNewsController();
        addPreferencesFromResource(R.xml.brave_news_sources_default);
        getActivity().setTitle(categoryArg);

        categsPublishers = new TreeMap<>();
        preferenceManager =  getPreferenceManager();
        mBraveNewsController.getPublishers((publishers) -> {
            List<Publisher> allPublishers = new ArrayList<>();
            List<Publisher> categoryPublishers = new ArrayList<>();
            for (Map.Entry<String,Publisher> entry : publishers.entrySet()) {
                String key = entry.getKey();

                Publisher publisher = entry.getValue();
                if (publisher.categoryName.toLowerCase(Locale.ROOT).equals(categoryArg.toLowerCase(Locale.ROOT))){
                    // categsPublishers.computeIfAbsent(publisher.categoryName, k ->new ArrayList<>()).add(publisher);
                    categoryPublishers.add(publisher);                    
                }

                categsPublishers.put(publisher.categoryName, categoryPublishers);                
                allPublishers.add(publisher);

            }
            Comparator<Publisher> compareByName = (Publisher o1, Publisher o2) ->
                    o1.publisherName.compareTo( o2.publisherName );
            Collections.sort(categoryPublishers, compareByName);
            Collections.sort(allPublishers, compareByName);
            categsPublishers.put("All Sources", allPublishers);

            addCategs(categsPublishers);
        });

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

    private void addCategs(TreeMap <String, List<Publisher>> publisherCategories){
        PreferenceScreen sourcesScreen = getPreferenceScreen();

        SearchPreference search = new SearchPreference(ContextUtils.getApplicationContext()); 
        search.setKey("search_pref");

        sourcesScreen.addPreference(search); 
        
        for(Map.Entry<String,List<Publisher>> map : publisherCategories.entrySet()){
            String category = map.getKey();
            if (category.toLowerCase(Locale.ROOT).equals(categoryArg.toLowerCase(Locale.ROOT))){

                List<Publisher> publishers = map.getValue();

                search.setOnPreferenceChangeListener(new Preference.OnPreferenceChangeListener() {
                    @Override
                    public boolean onPreferenceChange(Preference preference, Object newValue) {
                        for (Publisher publisher : publishers){
                            SwitchPreference publisherSource = preferenceManager.findPreference(publisher.publisherName);
                            if (publisher.publisherName.toLowerCase(Locale.ROOT).contains((String) newValue)){
                                publisherSource.setVisible(true);
                            } else {
                                publisherSource.setVisible(false);
                            }
                        }
                        return false;
                    }
                });

                for (Publisher publisher : publishers){

                    //Log.d("bn", "lonpressing disable publisher: "+publisher.publisherName + " publisher.isEnabled:" + publisher.isEnabled + " publisher.userEnabledStatus:" + publisher.userEnabledStatus);
                    SwitchPreference source = new SwitchPreference(ContextUtils.getApplicationContext()); 
                    source.setOnPreferenceChangeListener(null);
                    boolean enabled = false;
                    if (publisher.userEnabledStatus == UserEnabled.ENABLED){
                        enabled = true;
                    } else if (publisher.userEnabledStatus == UserEnabled.NOT_MODIFIED) {
                        enabled = publisher.isEnabled;
                    }                   
                    source.setTitle(publisher.publisherName);
                    source.setKey(publisher.publisherName);
                    source.setChecked(enabled);
                    source.setOnPreferenceChangeListener(new Preference.OnPreferenceChangeListener() {
                        @Override
                        public boolean onPreferenceChange(Preference preference, Object newValue) {
                            @UserEnabled.EnumType int type = UserEnabled.NOT_MODIFIED;
                            Log.d("bn", "lonpressing disable onPreferenceChange: " +newValue);
                            if ((boolean) newValue){
                                type = UserEnabled.ENABLED;
                            } else {
                                type = UserEnabled.DISABLED;
                            }

                            SharedPreferencesManager.getInstance().writeBoolean(BravePreferenceKeys.BRAVE_NEWS_CHANGE_SOURCE, true);

                            if (mBraveNewsController != null){
                                mBraveNewsController.setPublisherPref(publisher.publisherId, type);
                            }


                            source.setChecked((boolean) newValue);
                            return false;
                        }
                    });
                    sourcesScreen.addPreference(source); 
                }
            }
        }
    }
}
