
/* Copyright (c) 2021 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.chromium.chrome.browser.brave_news;

import android.os.Bundle;

import androidx.fragment.app.Fragment;
import org.chromium.chrome.R;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import org.chromium.base.Log;
import android.widget.TextView;
import android.widget.Button;
import org.chromium.base.Log;
import android.content.Context;
import org.chromium.chrome.browser.util.TabUtils;
import android.widget.Toast;
import org.chromium.chrome.browser.preferences.SharedPreferencesManager;
import org.chromium.chrome.browser.preferences.BravePreferenceKeys;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import com.google.android.material.bottomsheet.BottomSheetDialogFragment;

import org.chromium.brave_news.mojom.UserEnabled;
import org.chromium.brave_news.mojom.BraveNewsController;



public class BraveNewsBottomSheetDialogFragment extends BottomSheetDialogFragment {

    private String url;
    private String publisherId;
    private String publisherName;
    private BraveNewsController mBraveNewsController;
    private Context mContext;

    public static BraveNewsBottomSheetDialogFragment newInstance() {
        return new BraveNewsBottomSheetDialogFragment();
    }

    public void setController(BraveNewsController controller) {
        mBraveNewsController = controller;
    }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                             Bundle savedInstanceState) {
        if (getArguments() != null) {
            url = getArguments().getString("url");
            publisherId = getArguments().getString("publisherId");
            publisherName = getArguments().getString("publisherName");
        }
        View view = inflater.inflate(R.layout.brave_news_card_menu, container, false);
        return view;
    }

    @Override
    public void onAttach(Context context) {
        super.onAttach(context);
        mContext = context;
    }

    @Override
        public void onDetach() {
        super.onDetach();
        mContext = null;
    }    

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);

        TextView title = view.findViewById(R.id.item_menu_title_text);
        Button newTab = view.findViewById(R.id.new_tab);
        Button privateTab = view.findViewById(R.id.new_private_tab);
        Button disable = view.findViewById(R.id.disable_content);

        title.setText(url);
        StringBuilder disableText = new StringBuilder(R.string.brave_news_disable_content);
        disableText.append(" ");
        disableText.append(publisherName);
        disable.setText(disableText);

        newTab.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                TabUtils.openUrlInNewTab(false, url);
                dismiss();
            }
        });

        privateTab.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                TabUtils.openUrlInNewTab(true, url);
                dismiss();
            }
        });

        disable.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (mBraveNewsController != null){
                    // @UserEnabled.EnumType int type = UserEnabled.NOT_MODIFIED;
                    Log.d("bn", "lonpressing disable mBraveNewsController:"+mBraveNewsController + " publisherId:" + publisherId);

                    SharedPreferencesManager.getInstance().writeBoolean(BravePreferenceKeys.BRAVE_NEWS_CHANGE_SOURCE, true);
                    mBraveNewsController.setPublisherPref(publisherId, UserEnabled.DISABLED);
                }
                dismiss();
                Toast.makeText(mContext, publisherName + " disabled", Toast.LENGTH_SHORT).show();
            }
        });
    }
}
