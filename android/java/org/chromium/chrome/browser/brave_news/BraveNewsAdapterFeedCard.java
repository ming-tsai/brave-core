/* Copyright (c) 2021 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.chromium.chrome.browser.brave_news;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.Typeface;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.LayerDrawable;
import android.graphics.drawable.ShapeDrawable;
import android.graphics.drawable.shapes.RoundRectShape;
import android.net.Uri;
import android.os.Build;
import android.text.TextUtils;
import android.util.DisplayMetrics;
import android.util.Log;
import android.view.Gravity;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TableLayout;
import android.widget.TableRow;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;
import androidx.recyclerview.widget.RecyclerView;

import org.chromium.brave_news.mojom.Article;
import org.chromium.brave_news.mojom.BraveNewsController;
import org.chromium.brave_news.mojom.Deal;
import org.chromium.brave_news.mojom.FeedItem;
import org.chromium.brave_news.mojom.FeedItemMetadata;
import org.chromium.brave_news.mojom.PromotedArticle;
import org.chromium.chrome.R;
import org.chromium.chrome.browser.brave_news.BraveNewsControllerFactory;
import org.chromium.chrome.browser.brave_news.models.FeedItemCard;
import org.chromium.chrome.browser.brave_news.models.FeedItemsCard;
import org.chromium.chrome.browser.brave_news.models.NewsItem;
import org.chromium.chrome.browser.ntp.BraveNewTabPageLayout;
import org.chromium.chrome.browser.ntp_background_images.util.NTPUtil;
import org.chromium.mojo.bindings.ConnectionErrorHandler;
import org.chromium.mojo.system.MojoException;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ThreadLocalRandom;

public class BraveNewsAdapterFeedCard extends RecyclerView.Adapter<BraveNewsAdapterFeedCard.ViewHolder> {

    private LayoutInflater mInflater;
    public RecycleItemClickListener mClickListener;
    private int mType;
    private Context mContext;
    private Activity mActivity;
    private View view;
    private LinearLayout linearLayout;
    private LinearLayout.LayoutParams linearLayoutParams;

	// private CopyOnWriteArrayList<FeedItemCard> mNewsItems;
    private CopyOnWriteArrayList<FeedItemsCard> mNewsItems;
    // private FeedItemCard mNewsItem;
    private FeedItemsCard mNewsItem;
    private CopyOnWriteArrayList<FeedItemCard> mNewsItemsCard;
	private ViewHolder mHolder;
    private final String TAG = "BN";

    private BraveNewsController mBraveNewsController;

    public BraveNewsAdapterFeedCard(Activity activity,
            CopyOnWriteArrayList<FeedItemsCard> newsItems,
            BraveNewsController braveNewsController) {
        this.mInflater = LayoutInflater.from(activity);
        this.mActivity = activity;
        this.mNewsItems = newsItems;
        this.mBraveNewsController = braveNewsController;
        Log.d("bn", " BraveNewsAdapterFeedCard newsItems:" + newsItems);
    }

    @NonNull
    @Override
    public ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        Log.d("bn", "onCreateViewHolder viewType:" + viewType);
        view = mInflater.inflate(R.layout.brave_news_row, parent, false);
        mHolder = new ViewHolder(view);

        return mHolder;
    }

    @Override
    public void onBindViewHolder(@NonNull BraveNewsAdapterFeedCard.ViewHolder holder, int position) {
        LinearLayout.LayoutParams params1;
        if (mNewsItems != null){
            mNewsItem = mNewsItems.get(position);
            Log.d("bn", "createfeed BraveNewsAdapterFeedCard onBindViewHolder position: ------------- " + position);
            Log.d("bn", "createfeed BraveNewsAdapterFeedCard onBindViewHolder position item:" + mNewsItems.get(position));
            Log.d("bn", "createfeed BraveNewsAdapterFeedCard onBindViewHolder mNewsItem position: "+ position+" TYPE:" + mNewsItems.get(position).getCardType());
            // Log.d("BN", "onBindViewHolder getItemViewType:" + holder.getItemViewType());
            NTPUtil.showItemInfo(mNewsItems.get(position), "createfeed BraveNewsAdapterFeedCard onBindViewHolder position");

            try {
                // if (mBraveNewsController != null && mNewsItems.get(position) != null  && mNewsItems.get(position).getFeedItems() != null) {
                
                if (mBraveNewsController != null) {
                    new CardBuilderFeedCard(mBraveNewsController, mHolder.linearLayout, mActivity,
                            position, mNewsItems.get(position),
                            mNewsItems.get(position).getCardType());
                }
                
            } catch (Exception e) {
                Log.d("bn", "crashinvestigation onBindViewHolder e: " + e);
            }
        } 
    }

    @Override
    public int getItemCount() {
        return mNewsItems.size();
    }


    public void setClickListener(BraveNewTabPageLayout recyclerMain) {
        this.mClickListener = recyclerMain;
    }

    public class ViewHolderWidget extends RecyclerView.ViewHolder {
        ViewHolderWidget(View itemView) {
            super(itemView);
        }
    }

    public class ViewHolder extends RecyclerView.ViewHolder implements View.OnClickListener {
        LinearLayout linearLayout;

        ViewHolder(View itemView) {
            super(itemView);

            linearLayout = itemView.findViewById(R.id.card_layout);
            itemView.setOnClickListener(this);
        }

        @Override
        public void onClick(View view) {
            Log.d("bn", "cardclicklistener cliked on: "+getAdapterPosition());
            if (mClickListener != null) mClickListener.onCardClick(view, getAdapterPosition());
        }
    }

    public FeedItemsCard getItem(int id) {
        return mNewsItems.get(id);
    }


    public interface RecycleItemClickListener {
        void onCardClick(View view, int position);

        void onOptInClick(View view);

        void onCloseClick(View view);
    }
}
