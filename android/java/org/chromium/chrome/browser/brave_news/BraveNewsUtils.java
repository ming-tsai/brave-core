/* Copyright (c) 2021 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.chromium.chrome.browser.brave_news;

import android.content.Context;
import android.os.Build;

import androidx.annotation.RequiresApi;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import org.chromium.base.Log;
import org.chromium.brave_news.mojom.Article;
import org.chromium.brave_news.mojom.CardType;
import org.chromium.brave_news.mojom.Deal;
import org.chromium.brave_news.mojom.FeedItem;
import org.chromium.brave_news.mojom.DisplayAd;
import org.chromium.brave_news.mojom.FeedItemMetadata;
import org.chromium.brave_news.mojom.FeedPage;
import org.chromium.brave_news.mojom.FeedPageItem;
import org.chromium.brave_news.mojom.Image;
import org.chromium.brave_news.mojom.PromotedArticle;
import org.chromium.brave_news.mojom.Publisher;
import org.chromium.chrome.browser.brave_news.models.FeedItemCard;
import org.chromium.chrome.browser.brave_news.models.FeedItemsCard;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Iterator;
import java.util.concurrent.CopyOnWriteArrayList;

public class BraveNewsUtils {
    private Context mContext;

    public BraveNewsUtils(Context context) {
        mContext = context;
    }

    private Publisher getPublisher(){
        Publisher publisher = null;

        return publisher;

    }

    public String getPromotionIdItem(FeedItemsCard items) {
        String creativeInstanceId = "null";
        if (items.getFeedItems() != null){            
            for (FeedItemCard itemCard : items.getFeedItems()) {
                FeedItem item = itemCard.getFeedItem();
                FeedItemMetadata itemMetaData = new FeedItemMetadata();
                switch (item.which()) {
                    case FeedItem.Tag.PromotedArticle:
                        PromotedArticle promotedArticle = item.getPromotedArticle();
                        FeedItemMetadata promotedArticleData = promotedArticle.data;
                        creativeInstanceId = promotedArticle.creativeInstanceId;
                        itemMetaData = promotedArticle.data;
                        break;
                }
            }
        }

        return creativeInstanceId;
    }

    public static void logFeedItem(FeedItemsCard items, String id){
        if (items != null) {
            if (items.getCardType() == CardType.DISPLAY_AD){
                DisplayAd displayAd = items.getDisplayAd();
                if (displayAd != null){                    
                    Log.d("bn", id + " DISPLAY_AD title: " + displayAd.title);
                }
            } else {
                if (items.getFeedItems() != null){       
                    int index = 0;          
                    for (FeedItemCard itemCard : items.getFeedItems()){
                        if (index > 50){
                            return;
                        }
                        FeedItem item = itemCard.getFeedItem();

                        FeedItemMetadata itemMetaData = new FeedItemMetadata();
                        switch(item.which()){
                            case FeedItem.Tag.Article:
                                
                                Article article = item.getArticle();
                                FeedItemMetadata articleData = article.data;
                                itemMetaData = article.data;
                                Log.d("bn", id + " articleData: " + articleData.title);
                                // Log.d("bn", id + " articleData categoryName: " + articleData.categoryName);
                                // Log.d("bn", id + " articleData description: " + articleData.description);
                                // Log.d("bn", id + " articleData publisher_name: " + articleData.publisherName);
                                break;
                            case FeedItem.Tag.PromotedArticle:
                                PromotedArticle promotedArticle = item.getPromotedArticle();
                                FeedItemMetadata promotedArticleData = promotedArticle.data;
                                String creativeInstanceId = promotedArticle.creativeInstanceId;
                                itemMetaData = promotedArticle.data;
                                // Log.d("bn", id+" PromotedArticle: " + promotedArticleData.title);
                                // Log.d("bn", id+" PromotedArticle categoryName: " +
                                // promotedArticleData.categoryName); Log.d("bn", "getfeed feed pages item type
                                // PromotedArticle creativeInstanceId: " + creativeInstanceId);
                                break;                                            
                            case FeedItem.Tag.Deal:
                                Deal deal = item.getDeal();
                                FeedItemMetadata dealData = deal.data;
                                String offersCategory = deal.offersCategory;
                                itemMetaData = deal.data;
                                // Log.d("bn", id+" Deal: " + dealData.title);
                                // Log.d("bn", id+" Deal categoryName: " + dealData.categoryName);
                                // Log.d("bn", "getfeed feed pages item type Deal offersCategory: " +
                                // offersCategory);
                                break;
                        }
                        index++;
                    }
                } 
            }
        } 
    }
}
