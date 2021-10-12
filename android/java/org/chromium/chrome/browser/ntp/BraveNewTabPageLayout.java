/* Copyright (c) 2019 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.chromium.chrome.browser.ntp;

import static org.chromium.ui.base.ViewUtils.dpToPx;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.ActivityInfo;
import android.content.res.ColorStateList;
import android.content.res.Configuration;
import android.graphics.Bitmap;
import android.graphics.Color;
import android.graphics.Point;
import android.graphics.Rect;
import android.graphics.drawable.BitmapDrawable;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.Html;
import android.text.Spannable;
import android.text.SpannableStringBuilder;
import android.text.TextUtils;
import android.util.AttributeSet;
import android.util.Base64;
import android.util.DisplayMetrics;
import org.chromium.chrome.browser.preferences.SharedPreferencesManager;
import androidx.preference.PreferenceManager;
import android.util.Pair;
import android.view.ContextMenu;
import android.view.Display;
import android.view.Gravity;
import android.view.LayoutInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewStub;
import android.view.ViewTreeObserver;
import android.widget.Button;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.cardview.widget.CardView;
import androidx.core.view.ViewCompat;
import androidx.core.widget.ImageViewCompat;
import androidx.core.widget.NestedScrollView;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentManager;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewpager.widget.ViewPager;

import com.airbnb.lottie.LottieAnimationView;
import com.google.android.material.floatingactionbutton.FloatingActionButton;

import org.json.JSONException;

import org.chromium.base.ContextUtils;
import org.chromium.base.Log;
import org.chromium.base.ThreadUtils;
import org.chromium.base.TraceEvent;
import org.chromium.base.supplier.Supplier;
import org.chromium.base.task.AsyncTask;
import org.chromium.brave_news.mojom.Article;
import org.chromium.brave_news.mojom.BraveNewsController;
import org.chromium.brave_news.mojom.CardType;
import org.chromium.brave_news.mojom.Deal;
import org.chromium.brave_news.mojom.Feed;
import org.chromium.brave_news.mojom.DisplayAd;
import org.chromium.brave_news.mojom.FeedItem;
import org.chromium.brave_news.mojom.FeedItemMetadata;
import org.chromium.brave_news.mojom.FeedPage;
import org.chromium.brave_news.mojom.FeedPageItem;
import org.chromium.brave_news.mojom.Image;
import org.chromium.brave_news.mojom.PromotedArticle;
import org.chromium.brave_news.mojom.Publisher;
import org.chromium.chrome.R;
import org.chromium.chrome.browser.BraveAdsNativeHelper;
import org.chromium.chrome.browser.BraveRewardsHelper;
import org.chromium.chrome.browser.ChromeTabbedActivity;
import org.chromium.chrome.browser.InternetConnection;
import org.chromium.chrome.browser.QRCodeShareDialogFragment;
import org.chromium.chrome.browser.app.BraveActivity;
import org.chromium.chrome.browser.brave_news.BraveNewsAdapterFeedCard;
import org.chromium.chrome.browser.brave_news.BraveNewsControllerFactory;
import org.chromium.chrome.browser.brave_news.BraveNewsUtils;
import org.chromium.chrome.browser.brave_news.models.NewsFeedResponse;
import org.chromium.chrome.browser.brave_news.models.FeedItemCard;
import org.chromium.chrome.browser.brave_news.models.FeedItemsCard;
import org.chromium.chrome.browser.brave_news.models.NewsItem;
import org.chromium.chrome.browser.brave_stats.BraveStatsUtil;
import org.chromium.chrome.browser.compositor.CompositorViewHolder;
import org.chromium.chrome.browser.compositor.layouts.OverviewModeBehavior;
import org.chromium.chrome.browser.custom_layout.VerticalViewPager;
import org.chromium.chrome.browser.explore_sites.ExploreSitesBridge;
import org.chromium.chrome.browser.lifecycle.ActivityLifecycleDispatcher;
import org.chromium.chrome.browser.local_database.DatabaseHelper;
import org.chromium.chrome.browser.local_database.TopSiteTable;
import org.chromium.chrome.browser.native_page.ContextMenuManager;
import org.chromium.chrome.browser.night_mode.GlobalNightModeStateProviderHolder;
import org.chromium.chrome.browser.ntp.NewTabPageLayout;
import org.chromium.chrome.browser.ntp.widget.NTPWidgetAdapter;
import org.chromium.chrome.browser.ntp.widget.NTPWidgetItem;
import org.chromium.chrome.browser.ntp.widget.NTPWidgetManager;
import org.chromium.chrome.browser.ntp.widget.NTPWidgetStackActivity;
import org.chromium.chrome.browser.ntp_background_images.NTPBackgroundImagesBridge;
import org.chromium.chrome.browser.ntp_background_images.model.BackgroundImage;
import org.chromium.chrome.browser.ntp_background_images.model.NTPImage;
import org.chromium.chrome.browser.ntp_background_images.model.SponsoredTab;
import org.chromium.chrome.browser.ntp_background_images.model.TopSite;
import org.chromium.chrome.browser.ntp_background_images.model.Wallpaper;
import org.chromium.chrome.browser.ntp_background_images.util.FetchWallpaperWorkerTask;
import org.chromium.chrome.browser.ntp_background_images.util.NTPUtil;
import org.chromium.chrome.browser.ntp_background_images.util.NewTabPageListener;
import org.chromium.chrome.browser.ntp_background_images.util.SponsoredImageUtil;
import org.chromium.chrome.browser.offlinepages.DownloadUiActionFlags;
import org.chromium.chrome.browser.offlinepages.OfflinePageBridge;
import org.chromium.chrome.browser.offlinepages.RequestCoordinatorBridge;
import org.chromium.chrome.browser.onboarding.OnboardingPrefManager;
import org.chromium.chrome.browser.preferences.BravePref;
import org.chromium.chrome.browser.preferences.BravePrefServiceBridge;
import org.chromium.chrome.browser.preferences.BravePreferenceKeys;
import org.chromium.chrome.browser.preferences.SharedPreferencesManager;
import org.chromium.chrome.browser.profiles.Profile;
import org.chromium.chrome.browser.settings.BraveNewsPreferences;
import org.chromium.chrome.browser.settings.SettingsLauncherImpl;
import org.chromium.chrome.browser.suggestions.tile.TileGroup;
import org.chromium.chrome.browser.sync.settings.BraveManageSyncSettings;
import org.chromium.chrome.browser.tab.EmptyTabObserver;
import org.chromium.chrome.browser.tab.Tab;
import org.chromium.chrome.browser.tab.TabAttributes;
import org.chromium.chrome.browser.tab.TabImpl;
import org.chromium.chrome.browser.tab.TabObserver;
import org.chromium.chrome.browser.tabmodel.TabModel;
import org.chromium.chrome.browser.util.ConfigurationUtils;
import org.chromium.chrome.browser.util.PackageUtils;
import org.chromium.chrome.browser.util.TabUtils;
import org.chromium.chrome.browser.widget.crypto.binance.BinanceAccountBalance;
import org.chromium.chrome.browser.widget.crypto.binance.BinanceNativeWorker;
import org.chromium.chrome.browser.widget.crypto.binance.BinanceObserver;
import org.chromium.chrome.browser.widget.crypto.binance.BinanceWidgetManager;
import org.chromium.chrome.browser.widget.crypto.binance.CryptoWidgetBottomSheetDialogFragment;
import org.chromium.components.browser_ui.settings.SettingsLauncher;
import org.chromium.components.browser_ui.widget.displaystyle.UiConfig;
import org.chromium.components.embedder_support.util.UrlUtilities;
import org.chromium.components.user_prefs.UserPrefs;
import org.chromium.mojo.bindings.ConnectionErrorHandler;
import org.chromium.mojo.system.MojoException;
import org.chromium.ui.base.WindowAndroid;
import org.chromium.ui.widget.Toast;
import org.chromium.url.mojom.Url;
import android.content.SharedPreferences;

import java.util.ArrayList;
import java.util.List;
import java.util.Collections;
import java.util.Locale;
import java.util.Map;
import java.util.Timer;
import java.util.Locale;
import java.util.TimerTask;
import java.util.TreeMap;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import org.chromium.chrome.browser.preferences.BravePrefServiceBridge;


public class BraveNewTabPageLayout
        extends NewTabPageLayout implements CryptoWidgetBottomSheetDialogFragment
                                                    .CryptoWidgetBottomSheetDialogDismissListener,
                                            BraveNewsAdapterFeedCard.RecycleItemClickListener,
                                            ConnectionErrorHandler {
    private static final String TAG = "BraveNewTabPageView";
    private static final String BRAVE_BINANCE = "https://brave.com/binance/";
    private static final String BRAVE_REF_URL = "https://brave.com/r/";
    private static final int ITEMS_PER_PAGE = 18;
    private static final int MINIMUM_VISIBLE_HEIGHT_THRESHOLD = 50;

    private SharedPreferences.OnSharedPreferenceChangeListener sharedPreferencesListener;

    private View mBraveStatsViewFallBackLayout;

    private ImageView bgImageView;
    private Profile mProfile;
    private BraveNewTabPageLayout ntpLayout;
    private BraveNewTabPageLayout ntpContent;
    private LinearLayout parentLayout;

    private SponsoredTab sponsoredTab;

    private BitmapDrawable imageDrawable;

    private FetchWallpaperWorkerTask mWorkerTask;
    private boolean isFromBottomSheet;
    private NTPBackgroundImagesBridge mNTPBackgroundImagesBridge;
    private ViewGroup mainLayout;
    private DatabaseHelper mDatabaseHelper;

    private ViewGroup mSiteSectionView;
    private TileGroup mTileGroup;
    private LottieAnimationView mBadgeAnimationView;
    private VerticalViewPager ntpWidgetViewPager;
    private NTPWidgetAdapter ntpWidgetAdapter;

    private Tab mTab;
    private Activity mActivity;
    private LinearLayout indicatorLayout;
    private LinearLayout superReferralSitesLayout;
    private LinearLayout ntpWidgetLayout;
    private LinearLayout bianceDisconnectLayout;
    private LinearLayout binanceWidgetLayout;
    private ProgressBar binanceWidgetProgress;
    private TextView mTopsiteErrorMessage;

    private BinanceNativeWorker mBinanceNativeWorker;
    private CryptoWidgetBottomSheetDialogFragment cryptoWidgetBottomSheetDialogFragment;
    private Timer countDownTimer;
    private List<NTPWidgetItem> widgetList = new ArrayList<NTPWidgetItem>();
    public static final int NTP_WIDGET_STACK_CODE = 3333;

    // Brave news
    private BraveNewsAdapterFeedCard adapterFeedCard;
    private FrameLayout optinButton;
    private TextView optinText;
    private LinearLayout optinLayout;
    private TextView optinLearnMore;
    private ImageView optinClose;
    private CopyOnWriteArrayList<NewsItem> newsItems = new CopyOnWriteArrayList<NewsItem>();
    private CopyOnWriteArrayList<FeedItem> newsItemsFeed = new CopyOnWriteArrayList<FeedItem>();
    private CopyOnWriteArrayList<FeedItemsCard> newsItemsFeedCard = new CopyOnWriteArrayList<FeedItemsCard>();
    private CopyOnWriteArrayList<FeedItemsCard> newsRecyclerItems = new CopyOnWriteArrayList<FeedItemsCard>();
    private LinearLayout container;
    private RecyclerView recyclerView;
    // private NestedScrollView nestedScrollView;
    private TextView loading;
    private View loadingView;
    private View feedSpinner;
    private ScrollView parentScrollView;
    private ViewGroup imageCreditLayout;
    private ViewGroup settingsBar;
    private ViewGroup newContentButton;
    private boolean isScrolled;
    private NTPImage ntpImageGlobal;
    private boolean settingsBarIsClickable;
    private BraveNewsController mBraveNewsController;
    private BraveNewsUtils braveNewsUtils;

    private CompositorViewHolder compositorView;

    private long startCardViewTime;
    private long endCardViewTime;
    private String creativeInstanceId;
    private String uuid;
    //@TODO alex make an enum
    private String cardType;
    private int itemPosition;
    private FeedItemsCard visibleCard;
    private boolean isNewsOn;
    private boolean isShowOptin;
    private boolean isShowNewsOn;
    private int viewedNewsCardsCount;   

    private boolean isFeedLoaded;
    private CopyOnWriteArrayList<FeedItemsCard> existingNewsFeedObject;
    private int prevScrollPosition;
    private int oldFirstPos; 
    private int oldLastPos ;
    private int totalItemsViewed;
    private static int firstVisiblCard;
    private static int y;
    private String feedHash;
    private boolean isFeedUpdateAvailable;
    private SharedPreferencesManager.Observer mPreferenceObserver;
    // private static int currentFirstVisible;

    public BraveNewTabPageLayout(Context context, AttributeSet attrs) {
        super(context, attrs);
        mProfile = Profile.getLastUsedRegularProfile();
        mNTPBackgroundImagesBridge = NTPBackgroundImagesBridge.getInstance(mProfile);
        mBinanceNativeWorker = BinanceNativeWorker.getInstance();
        mNTPBackgroundImagesBridge.setNewTabPageListener(newTabPageListener);
        mDatabaseHelper = DatabaseHelper.getInstance();
    }

    @Override
    protected void onFinishInflate() {
        super.onFinishInflate();
        Log.d("bn", "persistencetest lifecycle onFinishInflate");

        ntpWidgetLayout = findViewById(R.id.ntp_widget_layout);
        indicatorLayout = findViewById(R.id.indicator_layout);
        ntpWidgetViewPager = findViewById(R.id.ntp_widget_view_pager);
        ntpWidgetAdapter = new NTPWidgetAdapter();
        ntpWidgetAdapter.setNTPWidgetListener(ntpWidgetListener);
        ntpWidgetViewPager.setAdapter(ntpWidgetAdapter);

        SharedPreferences sharedPreferences = ContextUtils.getAppSharedPreferences();

        isNewsOn = BravePrefServiceBridge.getInstance().getNewsOptIn();
        isShowOptin = sharedPreferences.getBoolean(BraveNewsPreferences.PREF_SHOW_OPTIN, false);
        isShowNewsOn = BravePrefServiceBridge.getInstance().getShowNews();

        feedHash = "";
        isFeedUpdateAvailable = false;

        ntpWidgetViewPager.addOnPageChangeListener(new ViewPager.OnPageChangeListener() {
            @Override
            public void onPageScrolled(
                    int position, float positionOffset, int positionOffsetPixels) {}

            @Override
            public void onPageSelected(int position) {
                cancelTimer();
                if (NTPWidgetManager.getInstance().getBinanceWidget() == position) {
                    startTimer();
                }
                updateAndShowIndicators(position);
                NTPWidgetManager.getInstance().setNTPWidgetOrder(position);
            }

            @Override
            public void onPageScrollStateChanged(int state) {}
        });
        showWidgetBasedOnOrder();
        NTPUtil.showBREBottomBanner(this);
        InitBraveNewsController();
        braveNewsUtils = new BraveNewsUtils(BraveActivity.getBraveActivity());

        isFeedLoaded = BraveActivity.getBraveActivity().isLoadedFeed();
        existingNewsFeedObject  = BraveActivity.getBraveActivity().getNewsItemsFeedCards();
        // prevScrollPosition = BraveActivity.getBraveActivity().getNewsFeedScrollPosition();
        prevScrollPosition = 2;//SharedPreferencesManager.getInstance().readInt(Integer.toString(BraveActivity.getBraveActivity().getActivityTab().getId()));

        Log.d("bn", "ondetach onFinishInflate params isFeedLoaded:"+isFeedLoaded+" prevScrollPosition:"+prevScrollPosition+" existingNewsFeedObject:"+existingNewsFeedObject+ " newsItemsFeedCard:"+newsItemsFeedCard);

        if (isNewsOn && isShowNewsOn) {
            if (isFeedLoaded){
                if (existingNewsFeedObject != null){
                    newsItemsFeedCard = existingNewsFeedObject;
                }
            }
        }

/*
        if (isNewsOn && isShowNewsOn) {
            Log.d("bn", "ondetach onFinishInflate isNewsOn && isShowOptin");
            if (!isFeedLoaded){
                Log.d("bn", "ondetach onFinishInflate  feed not loaded:");
                SharedPreferencesManager.getInstance().writeInt(
                                BravePreferenceKeys.BRAVE_NEWS_CARDS_VIEWED, 0);
                Log.d("bn", "ondetach onFinishInflate getting feed...");
                getFeed();
                // existingNewsFeedObject = newsItemsFeedCard;
                // BraveActivity.getBraveActivity().setNewsItemsFeedCard(existingNewsFeedObject);
            } 
            else {
                Log.d("bn", "ondetach feed loaded:");
                if (existingNewsFeedObject != null){
                    Log.d("bn", "ondetach addandrefresh newsItemsFeedCard before" +  newsItemsFeedCard.size() + "existingNewsFeedObject: "+existingNewsFeedObject.size());
                    // newsItemsFeedCard.clear();
                    // newsItemsFeedCard.addAll(existingNewsFeedObject);
                    Log.d("bn", "ondetach feed loaded: added mActivity: " + mActivity + " mBraveNewsController: "+mBraveNewsController);     
                    adapterFeedCard =
                            new BraveNewsAdapterFeedCard(BraveActivity.getBraveActivity(), existingNewsFeedObject, mBraveNewsController);
                    adapterFeedCard.notifyDataSetChanged();
                }
                Log.d("bn", "ondetach feed loaded: newsItemsFeedCard: " + newsItemsFeedCard.size());
                // processFeed();
                // Log.d("bn", "persistencetest feed loaded: after process feed: " + newsItemsFeedCard.size());
                if (recyclerView != null) {
                    Log.d("bn", "persistencetest feed loaded: recyclerView not before runnable");
                    // recyclerView.post(new Runnable() {
                    //     public void run() {
                    //         adapterFeedCard.notifyDataSetChanged();
                    //     }
                    // });
                    recyclerView.post(new Runnable() {
                        @Override
                        public void run() {
                            int scrollPosition = prevScrollPosition + 1;
                            if (prevScrollPosition <= 1) {
                                scrollPosition = 2;
                            }
                            Log.d("bn", "ondetach feed loaded: recyclerView not null runnable parentScrollView:"+parentScrollView);
                //             Log.d("bn", "persistencetest feed loaded: runnable notify: " + newsItemsFeedCard.size());
                //             adapterFeedCard.notifyDataSetChanged();
                            // ((LinearLayoutManager) recyclerView.getLayoutManager()).scrollToPosition(prevScrollPosition);
                            // recyclerView.smoothScrollToPosition(scrollPosition);
                            if (parentScrollView != null){
                                Log.d("bn", "ondetach feed loaded: parentScrollView.scrollTo");
                                // parentScrollView.scrollTo(0, 500);  
                                // parentScrollView.fullScroll(ScrollView.FOCUS_UP);
                                parentScrollView.postDelayed(new Runnable() {
                                    @Override
                                    public void run() {
                                        parentScrollView.fullScroll(ScrollView.FOCUS_UP);
                                    }
                                }, 100);
                                parentScrollView.postDelayed(new Runnable() {
                                    @Override
                                    public void run() {
                                        recyclerView.scrollToPosition(prevScrollPosition + 1);
                                    }
                                }, 100);
                            } 
                            // ((LinearLayoutManager) recyclerView.getLayoutManager()).scrollTo(prevScrollPosition);
                        }
                    });
                }
                //     Log.d("bn", "persistencetest feed loaded: after runnable notify: " + newsItemsFeedCard.size());
            }


            // else {
            //     Log.d("bn", "ondetach onFinishInflate getting exisingfeed..." + existingNewsFeedObject.size());
            //     if (existingNewsFeedObject != null){
            //         Log.d("bn", "persistencetest addandrefresh 1");
            //         newsItemsFeedCard.clear();
            //         newsItemsFeedCard.addAll(existingNewsFeedObject);
            //         // Collections.copy(newsItemsFeedCard,newsItemsFeedCard);
            //         Log.d("bn", "ondetach onFinishInflate getting exisingfeed. before.." + newsItemsFeedCard.size() + " adapterFeedCard:" + adapterFeedCard);
            //         adapterFeedCard =
            //                 new BraveNewsAdapterFeedCard(mActivity, newsItemsFeedCard, mBraveNewsController);
            //         Log.d("bn", "ondetach onFinishInflate getting exisingfeed. after.." + newsItemsFeedCard.size() + " adapterFeedCard:" + adapterFeedCard);

            //         adapterFeedCard.notifyDataSetChanged();
            //     }

            //     Log.d("bn", "persistencetest onFinishInflate feed loaded:" +newsItemsFeedCard.size() + " adapterFeedCard:"+ adapterFeedCard + " prevScrollPosition:"+ prevScrollPosition + " recyclerview:"+recyclerView);
            // }
        } else {
            Log.d("bn", "ondetach onFinishInflate false isNewsOn && isShowOptin: " + isNewsOn + "  " + isShowOptin);
        }
*/
        // initNews();

        if (BraveActivity.getBraveActivity() != null && isNewsOn) {
            Tab tab = BraveActivity.getBraveActivity().getActivityTab();
            if (tab != null && tab.getUrl().getSpec() != null
                    && UrlUtilities.isNTPUrl(tab.getUrl().getSpec())) {
                BraveActivity.getBraveActivity().inflateNewsSettingsBar();
            } else {
                Log.d("bn", "inflateNewsSettingsBar else remove move it");
                BraveActivity.getBraveActivity().removeSetttingsBar();
            } 
            // BraveActivity.getBraveActivity().inflateNewsSettingsBar();
            Log.d("bn", "inflatedSettingsBarLayout: " + BraveActivity.getBraveActivity().inflatedSettingsBarLayout + " compositorview:" + BraveActivity.getBraveActivity().compositorView) ;
        } 
     }

    private void showFallBackNTPLayout() {
        if (mBraveStatsViewFallBackLayout != null
                && mBraveStatsViewFallBackLayout.getParent() != null) {
            ((ViewGroup) mBraveStatsViewFallBackLayout.getParent())
                    .removeView(mBraveStatsViewFallBackLayout);
        }
        LayoutInflater inflater =
                (LayoutInflater) mActivity.getSystemService(Context.LAYOUT_INFLATER_SERVICE);
        mBraveStatsViewFallBackLayout = inflater.inflate(R.layout.brave_stats_layout, null);
        LinearLayout.LayoutParams layoutParams = new LinearLayout.LayoutParams(
            new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT));
        layoutParams.setMargins(0, dpToPx(mActivity, 16), 0, dpToPx(mActivity, 16));
        mBraveStatsViewFallBackLayout.setLayoutParams(layoutParams);
        mBraveStatsViewFallBackLayout.requestLayout();

        mBraveStatsViewFallBackLayout.findViewById(R.id.brave_stats_title_layout)
                .setVisibility(View.GONE);
        ((TextView) mBraveStatsViewFallBackLayout.findViewById(R.id.brave_stats_text_ads))
                .setTextColor(mActivity.getResources().getColor(R.color.shield_text_color));
        ((TextView) mBraveStatsViewFallBackLayout.findViewById(R.id.brave_stats_data_saved_text))
                .setTextColor(mActivity.getResources().getColor(R.color.shield_text_color));
        ((TextView) mBraveStatsViewFallBackLayout.findViewById(R.id.brave_stats_text_time))
                .setTextColor(mActivity.getResources().getColor(R.color.shield_text_color));
        ((TextView) mBraveStatsViewFallBackLayout.findViewById(R.id.brave_stats_text_time_count))
                .setTextColor(mActivity.getResources().getColor(R.color.shield_text_color));
        ((TextView) mBraveStatsViewFallBackLayout.findViewById(
                 R.id.brave_stats_text_time_count_text))
                .setTextColor(mActivity.getResources().getColor(R.color.shield_text_color));
        mBraveStatsViewFallBackLayout.setBackgroundColor(
                mActivity.getResources().getColor(android.R.color.transparent));
        mBraveStatsViewFallBackLayout.setOnClickListener(new View.OnClickListener() {
            @Override
            @SuppressLint("SourceLockedOrientationActivity")
            public void onClick(View v) {
                mActivity.setRequestedOrientation(ActivityInfo.SCREEN_ORIENTATION_PORTRAIT);
                checkForBraveStats();
            }
        });
        BraveStatsUtil.updateBraveStatsLayout(mBraveStatsViewFallBackLayout);
        mainLayout.addView(mBraveStatsViewFallBackLayout, 0);

        int insertionPoint = mainLayout.indexOfChild(findViewById(R.id.ntp_middle_spacer)) + 1;
        if (mSiteSectionView.getParent() != null) {
            ((ViewGroup) mSiteSectionView.getParent()).removeView(mSiteSectionView);
        }
        mainLayout.addView(mSiteSectionView, insertionPoint);
    }

    protected void updateTileGridPlaceholderVisibility() {
        // This function is kept empty to avoid placeholder implementation
    }

    private List<NTPWidgetItem> setWidgetList() {
        NTPWidgetManager ntpWidgetManager = NTPWidgetManager.getInstance();
        LayoutInflater inflater =
                (LayoutInflater) mActivity.getSystemService(Context.LAYOUT_INFLATER_SERVICE);
        Map<Integer, NTPWidgetItem> ntpWidgetMap = new TreeMap<>();
        if (mSiteSectionView != null && mSiteSectionView.getParent() != null) {
            ((ViewGroup) mSiteSectionView.getParent()).removeView(mSiteSectionView);
        }

        for (String widget : ntpWidgetManager.getUsedWidgets()) {
            NTPWidgetItem ntpWidgetItem = NTPWidgetManager.mWidgetsMap.get(widget);
            if (widget.equals(NTPWidgetManager.PREF_PRIVATE_STATS)) {
                View mBraveStatsView = inflater.inflate(R.layout.brave_stats_layout, null);
                mBraveStatsView.setOnClickListener(new View.OnClickListener() {
                    @Override
                    @SuppressLint("SourceLockedOrientationActivity")
                    public void onClick(View v) {
                        mActivity.setRequestedOrientation(ActivityInfo.SCREEN_ORIENTATION_PORTRAIT);
                        checkForBraveStats();
                    }
                });
                ntpWidgetItem.setWidgetView(mBraveStatsView);
                ntpWidgetMap.put(ntpWidgetManager.getPrivateStatsWidget(), ntpWidgetItem);
            } else if (widget.equals(NTPWidgetManager.PREF_FAVORITES)) {
                View mTopSitesLayout = inflater.inflate(R.layout.top_sites_layout, null);
                FrameLayout mTopSitesGridLayout =
                        mTopSitesLayout.findViewById(R.id.top_sites_grid_layout);
                mTopsiteErrorMessage =
                        mTopSitesLayout.findViewById(R.id.widget_error_title);

                if (shouldShowSuperReferral() && superReferralSitesLayout != null) {
                    if (superReferralSitesLayout.getParent() != null) {
                        ((ViewGroup) superReferralSitesLayout.getParent())
                                .removeView(superReferralSitesLayout);
                    }
                    mTopSitesGridLayout.addView(superReferralSitesLayout);
                    ntpWidgetItem.setWidgetView(mTopSitesLayout);
                    ntpWidgetMap.put(ntpWidgetManager.getFavoritesWidget(), ntpWidgetItem);
                } else if (!mNTPBackgroundImagesBridge.isSuperReferral()
                        || !NTPBackgroundImagesBridge.enableSponsoredImages()
                        || Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
                    boolean showPlaceholder = mTileGroup != null && mTileGroup.hasReceivedData()
                            && mTileGroup.isEmpty();
                    if (mSiteSectionView != null && !showPlaceholder) {
                        mTopsiteErrorMessage.setVisibility(View.GONE);
                        if (mSiteSectionView.getLayoutParams()
                                        instanceof ViewGroup.MarginLayoutParams) {
                            mSiteSectionView.setPadding(0, dpToPx(mActivity, 8), 0, 0);
                            mSiteSectionView.requestLayout();
                        }
                        mTopSitesGridLayout.addView(mSiteSectionView);
                    } else {
                        mTopsiteErrorMessage.setVisibility(View.VISIBLE);
                    }
                    ntpWidgetItem.setWidgetView(mTopSitesLayout);
                    ntpWidgetMap.put(ntpWidgetManager.getFavoritesWidget(), ntpWidgetItem);
                }
            } else if (widget.equals(NTPWidgetManager.PREF_BINANCE)) {
                View binanceWidgetView = inflater.inflate(R.layout.crypto_widget_layout, null);
                binanceWidgetLayout = binanceWidgetView.findViewById(R.id.binance_widget_layout);
                bianceDisconnectLayout =
                        binanceWidgetView.findViewById(R.id.binance_disconnect_layout);
                binanceWidgetProgress =
                        binanceWidgetView.findViewById(R.id.binance_widget_progress);
                binanceWidgetProgress.setVisibility(View.GONE);
                binanceWidgetView.setOnClickListener(new View.OnClickListener() {
                    @Override
                    public void onClick(View view) {
                        if (InternetConnection.isNetworkAvailable(mActivity)) {
                            if (BinanceWidgetManager.getInstance()
                                            .isUserAuthenticatedForBinance()) {
                                cancelTimer();
                                cryptoWidgetBottomSheetDialogFragment =
                                        new CryptoWidgetBottomSheetDialogFragment();
                                cryptoWidgetBottomSheetDialogFragment
                                        .setCryptoWidgetBottomSheetDialogDismissListener(
                                                BraveNewTabPageLayout.this);
                                cryptoWidgetBottomSheetDialogFragment.show(
                                        ((BraveActivity) mActivity).getSupportFragmentManager(),
                                        CryptoWidgetBottomSheetDialogFragment.TAG_FRAGMENT);
                            } else {
                                TabUtils.openUrlInSameTab(mBinanceNativeWorker.getOAuthClientUrl());
                                bianceDisconnectLayout.setVisibility(View.GONE);
                                binanceWidgetProgress.setVisibility(View.VISIBLE);
                            }
                        } else {
                            Toast.makeText(mActivity,
                                         mActivity.getResources().getString(
                                                 R.string.please_check_the_connection),
                                         Toast.LENGTH_SHORT)
                                    .show();
                        }
                    }
                });
                Button connectButton = binanceWidgetView.findViewById(R.id.btn_connect);
                connectButton.setOnClickListener(new View.OnClickListener() {
                    @Override
                    public void onClick(View view) {
                        TabUtils.openUrlInSameTab(mBinanceNativeWorker.getOAuthClientUrl());
                        bianceDisconnectLayout.setVisibility(View.GONE);
                        binanceWidgetProgress.setVisibility(View.VISIBLE);
                    }
                });
                ntpWidgetItem.setWidgetView(binanceWidgetView);
                ntpWidgetMap.put(ntpWidgetManager.getBinanceWidget(), ntpWidgetItem);
            }
        }

        return new ArrayList<NTPWidgetItem>(ntpWidgetMap.values());
    }

    private boolean shouldShowSuperReferral() {
        return mNTPBackgroundImagesBridge.isSuperReferral()
                && NTPBackgroundImagesBridge.enableSponsoredImages()
                && Build.VERSION.SDK_INT >= Build.VERSION_CODES.M;
    }

    private void showWidgetBasedOnOrder() {
        if (ntpWidgetViewPager != null) {
            int selectedOrder = NTPWidgetManager.getInstance().getNTPWidgetOrder();
            ntpWidgetViewPager.setCurrentItem(selectedOrder, true);
            updateAndShowIndicators(selectedOrder);
        }
    }

    private void showWidgets() {
        List<NTPWidgetItem> tempList = setWidgetList();
        if (tempList.size() > 0) {
            ntpWidgetLayout.setVisibility(View.VISIBLE);
            if (mBraveStatsViewFallBackLayout != null
                    && mBraveStatsViewFallBackLayout.getParent() != null) {
                ((ViewGroup) mBraveStatsViewFallBackLayout.getParent())
                        .removeView(mBraveStatsViewFallBackLayout);
            }
        } else {
            ntpWidgetLayout.setVisibility(View.GONE);
            if (!UserPrefs.get(Profile.getLastUsedRegularProfile())
                            .getBoolean(BravePref.NEW_TAB_PAGE_SHOW_BACKGROUND_IMAGE)) {
                showFallBackNTPLayout();
            }
        }

        if (ntpWidgetAdapter != null) {
            ntpWidgetAdapter.setWidgetList(tempList);
            ntpWidgetAdapter.notifyDataSetChanged();
            showWidgetBasedOnOrder();
        }
    }

    private void checkForBraveStats() {
        if (OnboardingPrefManager.getInstance().isBraveStatsEnabled()) {
            BraveStatsUtil.showBraveStats();
        } else {
            ((BraveActivity)mActivity).showOnboardingV2(true);
        }
    }

    @SuppressLint("VisibleForTests")
    protected void insertSiteSectionView() {
        mainLayout = findViewById(R.id.ntp_main_layout);

        mSiteSectionView = NewTabPageLayout.inflateSiteSection(mainLayout);
        ViewGroup.LayoutParams layoutParams = mSiteSectionView.getLayoutParams();
        layoutParams.width = ViewGroup.LayoutParams.WRAP_CONTENT;
        // If the explore sites section exists as its own section, then space it more closely.
        int variation = ExploreSitesBridge.getVariation();
        if (ExploreSitesBridge.isEnabled(variation)) {
            ((MarginLayoutParams) layoutParams).bottomMargin =
                getResources().getDimensionPixelOffset(
                    R.dimen.tile_grid_layout_vertical_spacing);
        }
        mSiteSectionView.setLayoutParams(layoutParams);
    }

    @Override
    protected void onAttachedToWindow() {
        Log.d("BN", "persistencetest lifecycle onAttachedToWindow");
        super.onAttachedToWindow();
        if (settingsBar != null) {
            Log.d("BN",
                    "lifecycle onAttachedToWindow settingsBar" + settingsBar.getAlpha()
                            + "setVisibility:" + settingsBar.getVisibility());
            settingsBar.setVisibility(View.VISIBLE);
            settingsBar.setAlpha(0f);
        }
        if (sponsoredTab == null) {
            initilizeSponsoredTab();
        }
        checkAndShowNTPImage(false);
        mNTPBackgroundImagesBridge.addObserver(mNTPBackgroundImageServiceObserver);
        if (PackageUtils.isFirstInstall(mActivity)
                && !OnboardingPrefManager.getInstance().isNewOnboardingShown()
                && OnboardingPrefManager.getInstance().isP3aOnboardingShown()) {
            ((BraveActivity)mActivity).showOnboardingV2(false);
        }
        if (OnboardingPrefManager.getInstance().isFromNotification() ) {
            ((BraveActivity)mActivity).showOnboardingV2(false);
            OnboardingPrefManager.getInstance().setFromNotification(false);
        }
        if (mBadgeAnimationView != null
                && !OnboardingPrefManager.getInstance().shouldShowBadgeAnimation()) {
            mBadgeAnimationView.setVisibility(View.INVISIBLE);
        }
        showWidgets();
        if (BinanceWidgetManager.getInstance().isUserAuthenticatedForBinance()) {
            if (binanceWidgetLayout != null) {
                binanceWidgetLayout.setVisibility(View.GONE);
            }
            mBinanceNativeWorker.getAccountBalances();
        }
        mBinanceNativeWorker.AddObserver(mBinanaceObserver);
        startTimer();
        initNews();
        if (BraveActivity.getBraveActivity() != null && isNewsOn) {
            Tab tab = BraveActivity.getBraveActivity().getActivityTab();
            if (tab != null && tab.getUrl().getSpec() != null
                    && UrlUtilities.isNTPUrl(tab.getUrl().getSpec())) {
                BraveActivity.getBraveActivity().inflateNewsSettingsBar();
            } else {
                Log.d("bn", "inflateNewsSettingsBar else remove move it");
                BraveActivity.getBraveActivity().removeSetttingsBar();
            } 
            // BraveActivity.getBraveActivity().inflateNewsSettingsBar();
            Log.d("bn", "settingsBarinvestigation inflatedSettingsBarLayout: " + BraveActivity.getBraveActivity().inflatedSettingsBarLayout + " compositorview:" + BraveActivity.getBraveActivity().compositorView) ;
        } 
        mPreferenceObserver = (key) -> {
            Log.d("bn", "newcontentchecks preference changed in bntpl for: "+key);
            if (TextUtils.equals(key, BravePreferenceKeys.BRAVE_NEWS_CHANGE_SOURCE)) {
                Log.d("bn", "newcontentchecks preference changed newContentButton: " + newContentButton);
                
                if (newContentButton != null) {
                    newContentButton.setVisibility(View.VISIBLE);
                }
            }
        };        
        SharedPreferencesManager.getInstance().addObserver(mPreferenceObserver);
    }   

    @Override
    protected void onDetachedFromWindow() {
        if (mWorkerTask != null && mWorkerTask.getStatus() == AsyncTask.Status.RUNNING) {
            mWorkerTask.cancel(true);
            mWorkerTask = null;
        }

        if (!isFromBottomSheet) {
            setBackgroundResource(0);
            if (imageDrawable != null && imageDrawable.getBitmap() != null && !imageDrawable.getBitmap().isRecycled()) {
                imageDrawable.getBitmap().recycle();
            }
        }
        mNTPBackgroundImagesBridge.removeObserver(mNTPBackgroundImageServiceObserver);
        mBinanceNativeWorker.RemoveObserver(mBinanaceObserver);
        cancelTimer();

        Log.d("bn", "ondetach newsItemsFeedCard:" + newsItemsFeedCard);
        if (newsItemsFeedCard != null && newsItemsFeedCard.size() > 0){
            BraveActivity.getBraveActivity().setNewsItemsFeedCards(newsItemsFeedCard);
        }

        Log.d("bn", "ondetach:" + settingsBar);
        if (settingsBar != null && compositorView != null) {
            // CompositorViewHolder compositorView = (CompositorViewHolder) rootView.getParent();
            if (settingsBar.getId() == R.id.news_settings_bar) {
                // compositorView.removeView(settingsBar);
                Log.d("bn", "ondetach b:" + settingsBar.getAlpha());
                settingsBar.setVisibility(View.GONE);
                settingsBar.setAlpha(0f);
                Log.d("bn", "ondetach a:" + settingsBar.getAlpha());
                // settingsBar.setVisibility(View.GONE);
                // compositorView.removeView(settingsBar);
            }
        } else {
            Log.d("bn", "ondetach null:" + settingsBar);
        }

        Log.d("bn", "newcontentchecks ondetach removing mPreferenceObserver:");
        SharedPreferencesManager.getInstance().removeObserver(mPreferenceObserver);
        mPreferenceObserver = null;

        super.onDetachedFromWindow();
    }

    @Override
    public void onConfigurationChanged(Configuration newConfig) {
        Log.d("BN", "onConfigurationChanged");
        if (sponsoredTab != null && NTPUtil.shouldEnableNTPFeature()) {
            if (bgImageView != null) {
                Log.d("BN", "onConfigurationChanged bgimage set");
                // We need to redraw image to fit parent properly
                // bgImageView.setImageResource(android.R.color.transparent);
            }
            NTPImage ntpImage = sponsoredTab.getTabNTPImage(false);
            if (ntpImage == null) {
                sponsoredTab.setNTPImage(SponsoredImageUtil.getBackgroundImage());
            } else if (ntpImage instanceof Wallpaper) {
                Wallpaper mWallpaper = (Wallpaper) ntpImage;
                if (mWallpaper == null) {
                    sponsoredTab.setNTPImage(SponsoredImageUtil.getBackgroundImage());
                }
            }
            checkForNonDisruptiveBanner(ntpImage);
            super.onConfigurationChanged(newConfig);
            showNTPImage(ntpImage);
        } else {
            super.onConfigurationChanged(newConfig);
        }
    }

    // corrects position of image credit and for the loading spinner. Used when News is active
    private void correctPosition(boolean toTop) {
        DisplayMetrics displayMetrics = getResources().getDisplayMetrics();
        float dpHeight = displayMetrics.heightPixels / displayMetrics.density;
        int pxHeight = dpToPx(mActivity, dpHeight);

        boolean isTablet = ConfigurationUtils.isTablet(mActivity);
        boolean isLandscape = ConfigurationUtils.isLandscape(mActivity);

        LinearLayout.LayoutParams linearLayoutParams =
                (LinearLayout.LayoutParams) imageCreditLayout.getLayoutParams();
        FrameLayout.LayoutParams feedSpinnerParams =
                (FrameLayout.LayoutParams) feedSpinner.getLayoutParams();
        FrameLayout bottomToolbar = (FrameLayout) findViewById(R.id.bottom_toolbar);
        // Log.d("bn",
        //         "onload - changing the layout positions before top marign :"
        //                 + linearLayoutParams.topMargin
        //                 + " feedSpinnerParams.topMargin:" + feedSpinnerParams.topMargin);

        int imageCreditCorrection = NTPUtil.correctImageCreditLayoutTopPosition(ntpImageGlobal) - 140;
        if (toTop) {
            imageCreditCorrection = 0;
        }

        Log.d("bn", "margintop imageCreditCorrection applied:" + imageCreditLayout.getHeight());
        linearLayoutParams.setMargins(0, imageCreditCorrection, 0, 0);
        // Log.d("bn", "margintop imageCreditCorrection:" + imageCreditLayout.getTop());
        // Log.d("bn", "margintop imageCreditCorrection:"+imageCreditLayout.getTop());
        imageCreditLayout.setLayoutParams(linearLayoutParams);
        int imageCreditLayoutBottom = imageCreditLayout.getBottom();
        feedSpinnerParams.topMargin = (int) (dpHeight
                - 30); // imageCreditLayoutBottom;// imageCreditLayout.getBottom() + 20;
        feedSpinner.setLayoutParams(feedSpinnerParams);
    }

    private void logFeedItem(FeedItemsCard items, String id){
        Log.d("bn",  id + " type " + items.getCardType());
        if (items != null) {
            if (items.getCardType() == CardType.DISPLAY_AD){
                DisplayAd displayAd = items.getDisplayAd();
                if (displayAd != null){                    
                    Log.d("bn", id + " DISPLAY_AD title: " + displayAd.title);
                    // Log.d("bn", id + " DISPLAY_AD description: " + displayAd.description);
                    // Log.d("bn", id + " DISPLAY_AD cta_text: " + displayAd.ctaText);
                }
            } else {
                if (items.getFeedItems() != null){
                    // Log.d("bn",
                    //     id + " type " + items.getCardType() + " size: " + items.getFeedItems().size()
                    //             + "uuid:" + items.getUuid() + " isViewStatSent:" + items.isViewStatSent());          
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

                                // braveNewsItems.add(article.data);
                               

                                Log.d("bn", id + " articleData: " + articleData.title);
                                // Log.d("bn", id + " articleData categoryName: " + articleData.categoryName);
                                // Log.d("bn", id + " articleData description: " + articleData.description);
                                // Log.d("bn", id + " articleData publisher_name: " + articleData.publisherName);
                                break;
                            case FeedItem.Tag.PromotedArticle:
                                PromotedArticle promotedArticle = item.getPromotedArticle();
                                FeedItemMetadata promotedArticleData = promotedArticle.data;
                                String creativeInstanceId = promotedArticle.creativeInstanceId;
                                // braveNewsItems.add(item.getPromotedArticle());
                                // braveNewsItems.add(promotedArticle.data);
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
                                // braveNewsItems.add(item.getDeal());
                                // braveNewsItems.add(deal.data);
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

    final AtomicInteger check = new AtomicInteger(0);
    ExecutorService executors = Executors.newFixedThreadPool(1);


    private Url getImage(FeedItemMetadata itemMetaData) {
        Url imageUrlTemp = null;
        switch(itemMetaData.image.which()){
            
            case Image.Tag.PaddedImageUrl:
                imageUrlTemp = itemMetaData.image.getPaddedImageUrl();
                if (imageUrlTemp != null){
                    // Log.d("bn", "createfeed feed pages item image padded: "+imageUrlTemp.url);
                }
                break;
            case Image.Tag.ImageUrl:
                imageUrlTemp = itemMetaData.image.getImageUrl();
                if (imageUrlTemp != null){
                    // Log.d("bn", "createfeed feed pages item image: "+imageUrlTemp.url);
                }
                break;
        }

        final Url finalImageUrl = imageUrlTemp;

        return finalImageUrl;
    }


    private void getFeedResponse(
            final RepositoryCallback<List<FeedItemsCard>> callback
    ) {
        ExecutorService executor = Executors.newSingleThreadExecutor();

        executor.execute(new Runnable() {
            @Override
            public void run() {
                try {
                    NewsFeedResponse<List<FeedItemsCard>> result = getFeedItemsResponse();
                    callback.onComplete(result);
                } catch (Exception e) {
                    NewsFeedResponse<List<FeedItemsCard>> errorResult = new NewsFeedResponse.ResponseError<>(e);
                    callback.onComplete(errorResult);
                }
            }
        });
    }

    private NewsFeedResponse<List<FeedItemsCard>> getFeedItemsResponse(){
        mBraveNewsController.getFeed((feed) -> {
            // ExecutorService executor = Executors.newSingleThreadExecutor();
            // Handler handler = new Handler(Looper.getMainLooper());

            // executor.execute(() -> {
            //     //Background work here
            //     Log.d("bn", "executor background work");


                FeedItemsCard featuredItemsCard = new FeedItemsCard();

                // process Featured item
                FeedItem featuredItem = feed.featuredItem;

                FeedItemMetadata featuredItemMetaData = new FeedItemMetadata();
                Article featuredArticle = featuredItem.getArticle();
                FeedItemMetadata featuredArticleData = featuredArticle.data;

                FeedItemCard featuredItemCard = new FeedItemCard();
                List<FeedItemCard> featuredCardItems = new ArrayList<>();

                featuredItemsCard.setCardType(CardType.HEADLINE);
                featuredItemsCard.setUuid(UUID.randomUUID().toString());

                featuredItemCard.setFeedItem(featuredItem);
                featuredCardItems.add(featuredItemCard);
                // Url featuredImageUrl = getImage(featuredArticleData);
                // mBraveNewsController.getImageData(featuredImageUrl, imageData -> {
                //     if (imageData != null){
                //         featuredItemCard.setImageByte(imageData);
                //     }
                // });

                featuredItemsCard.setFeedItems(featuredCardItems);
                newsItemsFeedCard.add(featuredItemsCard);

                // start page loop
                for (FeedPage page : feed.pages) {
                   
                       for (FeedPageItem cardData : page.items){
                            // Log.d("bn", "getfeed feed pages: " + cardData);

                            // Log.d("bn", "createfeed feed pages items: " + cardData.items);
                            // Log.d("bn", "createfeed feed pages items size: " + cardData.items.length);

                            if (cardData.cardType == CardType.DISPLAY_AD){
                                Log.d("bn",
                                        "createfeed feed pages type: "
                                                + cardData.cardType);
                                
                                mBraveNewsController.getDisplayAd( adData -> {
                                    Log.d("bn", "displayad:" + adData);
                                    if (adData != null){
                                        Log.d("bn", "displayad:" + adData.toString());
                                        Log.d("bn", "displayad:" + adData.dimensions);
                                        Log.d("bn", "displayad:" + adData.title);
                                        Log.d("bn", "displayad:" + adData.description);
                                        Log.d("bn", "displayad:" + adData.targetUrl);
                                        Log.d("bn", "displayad:" + adData.ctaText);
                                        Url imageUrlTemp = null;
                                        switch(adData.image.which()){
                                            case Image.Tag.PaddedImageUrl:
                                                imageUrlTemp = adData.image.getPaddedImageUrl();
                                                break;
                                            case Image.Tag.ImageUrl:
                                                imageUrlTemp = adData.image.getImageUrl();
                                                break;
                                        }

                                        final Url adImageUrl = imageUrlTemp;
                                        mBraveNewsController.getImageData(adImageUrl, imageData -> {
                                            if (imageData != null){
                                                // featuredItemCard.setImageByte(imageData);
                                            }
                                        }); 
                                    } else {
                                        
                                    }
                                });

                            }

                            FeedItemsCard feedItemsCard = new FeedItemsCard();
                            
                            feedItemsCard.setCardType(cardData.cardType);
                            feedItemsCard.setUuid(UUID.randomUUID().toString());
                            List<FeedItemCard> cardItems = new ArrayList<>();
                            for (FeedItem item : cardData.items){
                                
                                // Log.d("bn", "createfeed feed pages item: " + item);
                                // newsItemsFeed.add(item);

                                FeedItemMetadata itemMetaData = new FeedItemMetadata();
                                FeedItemCard feedItemCard = new FeedItemCard();
                                feedItemCard.setFeedItem(item);
                                // feedItemCard.setCardType(cardData.cardType);

                                cardItems.add(feedItemCard);
                                  
                                switch(item.which()){
                                    case FeedItem.Tag.Article:
                                        
                                        Article article = item.getArticle();
                                        FeedItemMetadata articleData = article.data;
                                        itemMetaData = article.data;

                                        // braveNewsItems.add(article.data);

                                        // Log.d("bn", "getfeed feed pages type
                                        // articleData: " + articleData.title);
                                        // Log.d("bn", "getfeed feed pages type
                                        // articleData: " + articleData.categoryName);
                                        break;
                                    case FeedItem.Tag.PromotedArticle:
                                        PromotedArticle promotedArticle = item.getPromotedArticle();
                                        FeedItemMetadata promotedArticleData = promotedArticle.data;
                                        String creativeInstanceId = promotedArticle.creativeInstanceId;
                                        // braveNewsItems.add(item.getPromotedArticle());
                                        // braveNewsItems.add(promotedArticle.data);
                                        itemMetaData = promotedArticle.data;
                                        // Log.d("bn", "getfeed feed pages item type
                                        // PromotedArticle: " +
                                        // promotedArticleData.title); Log.d("bn",
                                        // "getfeed feed pages item type
                                        // PromotedArticle: " +
                                        // promotedArticleData.categoryName);
                                        // Log.d("bn", "getfeed feed pages item type
                                        // PromotedArticle creativeInstanceId: " +
                                        // creativeInstanceId);
                                        break;                                            
                                    case FeedItem.Tag.Deal:
                                        Deal deal = item.getDeal();
                                        FeedItemMetadata dealData = deal.data;
                                        String offersCategory = deal.offersCategory;
                                        // braveNewsItems.add(item.getDeal());
                                        // braveNewsItems.add(deal.data);
                                        itemMetaData = deal.data;
                                        // Log.d("bn", "getfeed feed pages item type
                                        // Deal: " + dealData.title); Log.d("bn",
                                        // "getfeed feed pages item type Deal: " +
                                        // dealData.categoryName); Log.d("bn", "getfeed
                                        // feed pages item type Deal: " +
                                        // dealData.description); Log.d("bn", "getfeed
                                        // feed pages item type Deal: " +
                                        // dealData.publisherName); Log.d("bn", "getfeed
                                        // feed pages item type Deal offersCategory: " +
                                        // offersCategory);
                                        break;
                                }

                                Url imageUrlTemp = null;
                                switch(itemMetaData.image.which()){
                                    
                                    case Image.Tag.PaddedImageUrl:
                                        imageUrlTemp = itemMetaData.image.getPaddedImageUrl();
                                        if (imageUrlTemp != null){
                                            // Log.d("bn", "createfeed feed pages item image padded: "+imageUrlTemp.url);
                                        }
                                        break;
                                    case Image.Tag.ImageUrl:
                                        imageUrlTemp = itemMetaData.image.getImageUrl();
                                        if (imageUrlTemp != null){
                                            // Log.d("bn", "createfeed feed pages item image: "+imageUrlTemp.url);
                                        }
                                        break;
                                }

                                final Url imageUrl = imageUrlTemp;

                                // Log.d("bn", "thread imagesbeforeGet - "+i.get());  
                                // 
                                // if (index.get() < 1) { 
                                    // mBraveNewsController.getImageData(imageUrl, imageData -> {
                                    //     // Log.d("bn", "thread images processing - "+i.get());
                                    //     // Log.d("bn", "createfeed feed pages item getting image data: "+imageData + " imageUrl.url:" +imageUrl.url);
                                    //     if (imageData != null){
                                    //         feedItemCard.setImageByte(imageData);
                                    //         // newsItemsFeedCard.add(feedItemCard);
                                    //     }
                                    // });        
                                // }                                                
                                // Log.d("bn", "thread imagesafter - "+i.get());


                                feedItemsCard.setFeedItems(cardItems);
                                    
                            }                            
                            newsItemsFeedCard.add(feedItemsCard);
                        }
                    //}
                    // index.getAndIncrement();    
                }//end page loop
        
            // i.getAndIncrement();
            // Log.d("bn", "thread 3 - "+i.get());
        });

        Log.d("bn", "executortest newsItemsFeedCard.size(): " + newsItemsFeedCard.size());
        return new NewsFeedResponse.ResponseSuccess<List<FeedItemsCard>>(newsItemsFeedCard);
    }

    private void getFeed() {
        final AtomicInteger index = new AtomicInteger(0);
        final AtomicInteger i = new AtomicInteger(0);
        // int i=0;

        Runnable runnable = new Runnable() {
            @Override
            public void run() {
                    Log.d("bn", "persistencetest  newsItemsFeedCard.size(): " + newsItemsFeedCard.size());
                    mBraveNewsController.getFeed((feed) -> {
                        i.incrementAndGet();
                        if (feed == null) {
                            processFeed();
                            return;
                        }
                        try {
                            Log.d("bn", "thread 4 - " +i.get());
                            Log.d("bn", "newcontentchecks: feed: " + feed.hash);
                            feedHash = feed.hash;
                            SharedPreferencesManager.getInstance().writeString(BravePreferenceKeys.BRAVE_NEWS_FEED_HASH, feed.hash);
                            if (feed.featuredItem != null) {
                                // process Featured item
                                FeedItem featuredItem = feed.featuredItem;
                                FeedItemsCard featuredItemsCard = new FeedItemsCard();

                                FeedItemMetadata featuredItemMetaData = new FeedItemMetadata();
                                Article featuredArticle = featuredItem.getArticle();
                                FeedItemMetadata featuredArticleData = featuredArticle.data;

                                FeedItemCard featuredItemCard = new FeedItemCard();
                                List<FeedItemCard> featuredCardItems = new ArrayList<>();

                                featuredItemsCard.setCardType(CardType.HEADLINE);
                                featuredItemsCard.setUuid(UUID.randomUUID().toString());

                                featuredItemCard.setFeedItem(featuredItem);
                                featuredCardItems.add(featuredItemCard);

                                featuredItemsCard.setFeedItems(featuredCardItems);
                                newsItemsFeedCard.add(featuredItemsCard);

                            }

                            // adds empty card to trigger Display ad call for the second card, when the user starts scrolling
                            FeedItemsCard displayAdCard = new FeedItemsCard();
                            DisplayAd displayAd = new DisplayAd();
                            displayAdCard.setCardType(CardType.DISPLAY_AD);
                            displayAdCard.setDisplayAd(displayAd);
                            displayAdCard.setUuid(UUID.randomUUID().toString());
                            newsItemsFeedCard.add(displayAdCard);                                

                            // start page loop
                            int noPages = 0;
                            int itemIndex = 0;
                            int totalPages = feed.pages.length;
                            for (FeedPage page : feed.pages) {
                               
                                for (FeedPageItem cardData : page.items){
                                    // Log.d("bn", "getfeed feed pages: " + cardData);

                                    // Log.d("bn", "createfeed feed pages items: " + cardData.items);
                                    Log.d("bn", "createfeed PROMOTED_ARTICLE: " + cardData.cardType + "  " + itemIndex +" | ");
                                    // Log.d("bn", "createfeed PROMOTED_ARTICLE items :" + cardData.items + " size: " + cardData.items.length);
                                    if (cardData.cardType != CardType.DISPLAY_AD){
                                        if (cardData.items.length == 0){
                                            Log.d("bn", "createfeed PROMOTED_ARTICLE before continue");
                                            continue;
                                        }
                                    }
                                    Log.d("bn", "createfeed PROMOTED_ARTICLE after continue for index:"+itemIndex);
                                    
                                    FeedItemsCard feedItemsCard = new FeedItemsCard();
                                    
                                    if (cardData.cardType == CardType.DISPLAY_AD){
                                        Log.d("bn",
                                                "getfeed feed pages item type: " + cardData.cardType);
                                    }

                                    
                                    feedItemsCard.setCardType(cardData.cardType);
                                    feedItemsCard.setUuid(UUID.randomUUID().toString());
                                    List<FeedItemCard> cardItems = new ArrayList<>();
                                    for (FeedItem item : cardData.items){

                                        FeedItemMetadata itemMetaData = new FeedItemMetadata();
                                        FeedItemCard feedItemCard = new FeedItemCard();
                                        feedItemCard.setFeedItem(item);
                                        // feedItemCard.setCardType(cardData.cardType);

                                        cardItems.add(feedItemCard);
                                          
                                        switch(item.which()){
                                            case FeedItem.Tag.Article:
                                                
                                                Article article = item.getArticle();
                                                FeedItemMetadata articleData = article.data;
                                                itemMetaData = article.data;

                                                // braveNewsItems.add(article.data);

                                                // Log.d("bn", "getfeed feed pages type
                                                // articleData: " + articleData.title);
                                                // Log.d("bn", "getfeed feed pages type
                                                // articleData: " + articleData.categoryName);
                                                break;
                                            case FeedItem.Tag.PromotedArticle:
                                                PromotedArticle promotedArticle = item.getPromotedArticle();
                                                FeedItemMetadata promotedArticleData = promotedArticle.data;
                                                String creativeInstanceId = promotedArticle.creativeInstanceId;
                                                // braveNewsItems.add(item.getPromotedArticle());
                                                // braveNewsItems.add(promotedArticle.data);
                                                itemMetaData = promotedArticle.data;
                                                // Log.d("bn", "getfeed feed pages item type PromotedArticle: index: " +itemIndex+ "  promotedArticle:"  + promotedArticleData.title); 
                                                // Log.d("bn", "getfeed feed pages item type PromotedArticle: " + promotedArticleData.categoryName);
                                                // Log.d("bn", "getfeed feed pages item type PromotedArticle creativeInstanceId: " + creativeInstanceId);
                                                break;                                            
                                            case FeedItem.Tag.Deal:
                                                Deal deal = item.getDeal();
                                                FeedItemMetadata dealData = deal.data;
                                                String offersCategory = deal.offersCategory;
                                                // braveNewsItems.add(item.getDeal());
                                                // braveNewsItems.add(deal.data);
                                                itemMetaData = deal.data;
                                                // Log.d("bn", "getfeed feed pages item type Deal title: " + dealData.title); 
                                                // Log.d("bn", "getfeed feed pages item type Deal categoryName: " +dealData.categoryName); 
                                                // Log.d("bn", "getfeed feed pages item type Deal description: " + dealData.description); 
                                                // Log.d("bn", "getfeed feed pages item type Deal publisherName: " +dealData.publisherName); 
                                                // Log.d("bn", "getfeed feed pages item type Deal offersCategory: " + offersCategory);
                                                break;
                                        }

                                        Url imageUrlTemp = null;
                                        switch(itemMetaData.image.which()){
                                            
                                            case Image.Tag.PaddedImageUrl:
                                                imageUrlTemp = itemMetaData.image.getPaddedImageUrl();
                                                if (imageUrlTemp != null){
                                                    // Log.d("bn", "createfeed feed pages item image padded: "+imageUrlTemp.url);
                                                }
                                                break;
                                            case Image.Tag.ImageUrl:
                                                imageUrlTemp = itemMetaData.image.getImageUrl();
                                                if (imageUrlTemp != null){
                                                    // Log.d("bn", "createfeed feed pages item image: "+imageUrlTemp.url);
                                                }
                                                break;
                                        }

                                        feedItemsCard.setFeedItems(cardItems);
                                        itemIndex++;
                                            
                                    }                            
                                    newsItemsFeedCard.add(feedItemsCard);
                                }

                                index.getAndIncrement();    

                                Log.d("bn", "getfeedprocessing next page");
                                if(noPages == totalPages - 1){
                                    Log.d("bn", "getfeedprocessing last page");
                                }
                                noPages++;
                            }//end page loop
                            // existingNewsFeedObject = newsItemsFeedCard;
                            processFeed();
                            // Log.d("bn", "getfeedprocessing after page loop newsItemsFeedCard:"+newsItemsFeedCard);
                            BraveActivity.getBraveActivity().setNewsItemsFeedCards(newsItemsFeedCard);
                            BraveActivity.getBraveActivity().setLoadedFeed(true);
                            i.getAndIncrement();
                            Log.d("bn", "thread 3 - "+i.get());
                        } catch (Exception e) {
                            e.printStackTrace();
                            Log.e("bn", "Exception getting feed: " + e.getMessage());
                        }
                    });

                    i.getAndIncrement();
                    Log.d("bn", "thread 2 - "+i.get());
                    // Thread.sleep(100);
                    // handle response                 
                    Handler uiThread = new Handler(Looper.getMainLooper());
                    uiThread.post(new Runnable() {
                        @Override
                        public void run() {
                            i.getAndIncrement();
                            Log.d("bn", " thread - 4 finish " +i.get());
                           
                            // now update your UI here
                            // cast response to whatever you specified earlier
                        }
                    });

            }
        };
        executors.submit(runnable);
    }

    private void refreshFeed() {
        newsItemsFeedCard.clear();
        adapterFeedCard =
                new BraveNewsAdapterFeedCard(mActivity, newsItemsFeedCard, mBraveNewsController);
        recyclerView.setAdapter(adapterFeedCard);
        getFeed();
        parentScrollView.fullScroll(ScrollView.FOCUS_UP);
        recyclerView.scrollToPosition(0);
    }

    private void initNews() {
        Log.d("bn", "persistencetest in initNews");
        settingsBarIsClickable = false;
        recyclerView = findViewById(R.id.newsRecycler);
        container = (LinearLayout) findViewById(R.id.ntp_main_layout);
        optinButton = findViewById(R.id.optin_button);
        optinClose = findViewById(R.id.close_optin);
        optinLearnMore = findViewById(R.id.optin_learnmore);
        optinLayout = findViewById(R.id.optin_layout_id);
        optinText = findViewById(R.id.optin_button_text);
        loading = findViewById(R.id.loading);
        loadingView = findViewById(R.id.optin_loading_spinner);
        feedSpinner = findViewById(R.id.feed_spinner);
        parentLayout = (LinearLayout) findViewById(R.id.parent_layout);
        ntpContent = (BraveNewTabPageLayout) findViewById(R.id.ntp_content);

        SharedPreferencesManager.getInstance().writeBoolean(BravePreferenceKeys.BRAVE_NEWS_CHANGE_SOURCE, false);
        // init Brave news parameters
        startCardViewTime = 0;
        endCardViewTime = 0;
        creativeInstanceId = "";
        uuid = "";
        //@TODO alex make an enum
        cardType = "";
        itemPosition = 0;
        visibleCard = null;

        recyclerView.setItemViewCacheSize(250);
        // recyclerView.setHasFixedSize(true);
        recyclerView.setDrawingCacheEnabled(true);
        // recyclerView.setDrawingCacheQuality(View.DRAWING_CACHE_QUALITY_HIGH);

        recyclerView.setVisibility(View.GONE);
        // recyclerView.setScrollContainer(false);

        recyclerView.setLayoutManager(new LinearLayoutManager(mActivity));
        Log.d("bn", "ondetach onFinishInflate getting exisingfeed. initNews before adapterFeedCard:"+adapterFeedCard);
        adapterFeedCard =
                new BraveNewsAdapterFeedCard(mActivity, newsItemsFeedCard, mBraveNewsController);
        // adapterFeedCard.setHasStableIds(true);
        // adapterFeedCard = new BraveNewsAdapterFeedCard(mActivity, newsRecyclerItems);
        Log.d("bn", "ondetach onFinishInflate getting exisingfeed. initNews after adapterFeedCard:"+adapterFeedCard);
        recyclerView.setAdapter(adapterFeedCard);

        adapterFeedCard.setClickListener(this);
        loadingView.setVisibility(View.GONE);

        parentScrollView = (ScrollView) ntpContent.getParent();
        ViewGroup rootView = (ViewGroup) parentScrollView.getParent();
        compositorView = (CompositorViewHolder) rootView.getParent();

        Log.d("bn", "settingsBarinvestigation initnews compositorView: " + compositorView);

        imageCreditLayout = findViewById(R.id.image_credit_layout);

        optinLayout.setVisibility(View.GONE);
        SharedPreferences sharedPreferences = ContextUtils.getAppSharedPreferences();

        Log.d("bn", "persistencetest layout optin isNewsOn:" + isNewsOn + " isShowNewsOn:" + isShowNewsOn + " newsItemsFeedCard:" +newsItemsFeedCard.size());

        // if (!isNewsOn || (!isNewsOn && !isShowOptin) {
        if (!isNewsOn) {
            correctPosition(false);
            optinLayout.setVisibility(View.VISIBLE);
        } else if (!isNewsOn && isShowOptin) {
            correctPosition(false);
            optinLayout.setVisibility(View.VISIBLE);
            Log.d("bn", "persistencetest layout optin isNewsOn--");
        } else if (isShowNewsOn) {
            // correctPosition(false);

            optinLayout.setVisibility(View.GONE);
            parentLayout.removeView(optinLayout);
            feedSpinner.setVisibility(View.VISIBLE);

            boolean isFeedLoaded = BraveActivity.getBraveActivity().isLoadedFeed();
            CopyOnWriteArrayList<FeedItemsCard> existingNewsFeedObject  = BraveActivity.getBraveActivity().getNewsItemsFeedCards();
            // int prevScrollPosition = BraveActivity.getBraveActivity().getNewsFeedScrollPosition();
            int prevScrollPosition = SharedPreferencesManager.getInstance().readInt(Integer.toString(BraveActivity.getBraveActivity().getActivityTab().getId()));


            Log.d("bn", "testviewedcards viewedNewsCardsCount before shared prefs: " + viewedNewsCardsCount);
            Log.d("bn", "tabmanagement tabid: " + BraveActivity.getBraveActivity().getActivityTab().getId());
            Log.d("bn", "tabmanagement tabid getTabImpl: " + getTabImpl().getId() + " cangofwd: " +BraveActivity.getBraveActivity().getActivityTab().canGoForward() + " prevScrollPosition: "+prevScrollPosition);
            Log.d("bn", "tabmanagement tabid prevScrollPosition: " + prevScrollPosition);

            viewedNewsCardsCount = SharedPreferencesManager.getInstance().readInt(
                                            "viewedNewsCardsCount_"+BraveActivity.getBraveActivity().getActivityTab().getId());
            // if !canGoForward() means that it's a fresh NTP so we reset 
            // if (!BraveActivity.getBraveActivity().getActivityTab().canGoForward() || prevScrollPosition == 0) {
            if (prevScrollPosition == 0) {
                isFeedLoaded = false;
                existingNewsFeedObject = null;
                viewedNewsCardsCount = 0;
                // prevScrollPosition = -1;
            }

            Log.d("bn", "persistencetest before isFeedLoaded:"+isFeedLoaded+" prevScrollPosition:"+prevScrollPosition+" existingNewsFeedObject:"+existingNewsFeedObject);
  
            if (!isFeedLoaded){
                Log.d("bn", "persistencetest feed not loaded:");
                getFeed();
                SharedPreferencesManager.getInstance().writeInt(Integer.toString(BraveActivity.getBraveActivity().getActivityTab().getId()) , 1);
                // Brave News interaction started
                if (mBraveNewsController != null) {
                    mBraveNewsController.onInteractionSessionStarted();
                }
                
                // existingNewsFeedObject = newsItemsFeedCard;
                // BraveActivity.getBraveActivity().setNewsItemsFeedCard(existingNewsFeedObject);
            } 
            
            else {
                Log.d("bn", "persistencetest feed loaded mActivity:" + mActivity);
                if (mActivity == null) {
                    mActivity = BraveActivity.getBraveActivity();
                }
                setFeed();
                /*
                if (existingNewsFeedObject != null){
                    Log.d("bn", "persistencetest addandrefresh newsItemsFeedCard before" +  newsItemsFeedCard.size() + "existingNewsFeedObject:"+existingNewsFeedObject.size());
                    // newsItemsFeedCard.clear();
                    newsItemsFeedCard = existingNewsFeedObject;
                    // Collections.copy(newsItemsFeedCard,existingNewsFeedObject);
                    // newsItemsFeedCard.addAll(existingNewsFeedObject);
                    Log.d("bn", "persistencetest feed loaded: added  existingNewsFeedObject to newsItemsFeedCard: " + newsItemsFeedCard.size());     
                    // adapterFeedCard =
                    //         new BraveNewsAdapterFeedCard(mActivity, newsItemsFeedCard, mBraveNewsController);
                    // adapterFeedCard.notifyDataSetChanged();
                }
                Log.d("bn", "persistencetest feed loaded: getItemCount();: " + adapterFeedCard.getItemCount());
                if (adapterFeedCard.getItemCount() == 0){
                    Log.d("bn", "persistencetest feed loaded existingNewsFeedObject adapterFeedCard == 0: " + existingNewsFeedObject + " newsItemsFeedCard: " + newsItemsFeedCard);
                    // adapterFeedCard =
                    //         new BraveNewsAdapterFeedCard(mActivity, existingNewsFeedObject, mBraveNewsController);
                }
                Log.d("bn", "persistencetest feed loaded existingNewsFeedObject: getItemCount(): " + adapterFeedCard.getItemCount());
                        
                parentScrollView.postDelayed(new Runnable() {
                    @Override
                    public void run() {
                        processFeed();
                    }
                }, 100);
                */
                // Log.d("bn", "persistencetest feed loaded: after process feed: " + newsItemsFeedCard.size());
                if (recyclerView != null) {
                    Log.d("bn", "persistencetest feed loaded: recyclerView not before runnable");
                    
                    recyclerView.post(new Runnable() {
                        @Override
                        public void run() {
                            int scrollPosition = prevScrollPosition + 1;
                            if (prevScrollPosition <= 1) {
                                scrollPosition = 2;
                            }
                            final int scrollPositionFinal = scrollPosition;
                            Log.d("bn", "persistencetest feed loaded: recyclerView not null runnable parentScrollView:"+parentScrollView);
                //             Log.d("bn", "persistencetest feed loaded: runnable notify: " + newsItemsFeedCard.size());
                //             adapterFeedCard.notifyDataSetChanged();
                            // ((LinearLayoutManager) recyclerView.getLayoutManager()).scrollToPosition(prevScrollPosition);
                            // recyclerView.smoothScrollToPosition(scrollPosition);
                            if (parentScrollView != null){
                                Log.d("bn", "persistencetest feed loaded: parentScrollView.scrollTo");
                                // parentScrollView.scrollTo(0, 500);  
                                // parentScrollView.fullScroll(ScrollView.FOCUS_UP);
                                        parentScrollView.fullScroll(ScrollView.FOCUS_UP);
                                        recyclerView.scrollToPosition(scrollPositionFinal);
                                parentScrollView.postDelayed(new Runnable() {
                                    @Override
                                    public void run() {
                                    }
                                }, 10);
                                recyclerView.postDelayed(new Runnable() {
                                    @Override
                                    public void run() {
                                    }
                                }, 20);
                                imageCreditLayout.scrollTo(0,0);
                            } 
                            // correctPosition(true);
                            // ((LinearLayoutManager) recyclerView.getLayoutManager()).scrollTo(prevScrollPosition);
                        }
                    });
                }
                //     Log.d("bn", "persistencetest feed loaded: after runnable notify: " + newsItemsFeedCard.size());
            }
        
            // getFeedResponse( new RepositoryCallback<List<FeedItemsCard>>() {
            //     @Override
            //     public void onComplete(NewsFeedResponse<List<FeedItemsCard>> result) {

            //         Log.d("bn", "executortest result : "+ result);
            //         if (result instanceof NewsFeedResponse.ResponseSuccess) {
            //             // Happy path
            //             Log.d("bn", "executortest  success " +((NewsFeedResponse.ResponseSuccess<List<FeedItemsCard>>) result).data);
            //             // Log.d("bn", "executortest  success " +((Result.Success<Integer>) result).data);
            //         } else {
            //             // Show error in UI
            //             Log.d("bn", "executortest  Error");
            //         }
            //     }
            // });

 
        }

        ViewTreeObserver parentScrollViewObserver = parentScrollView.getViewTreeObserver();
        parentScrollView.getViewTreeObserver().addOnScrollChangedListener(
            new ViewTreeObserver.OnScrollChangedListener() {
                @Override
                public void onScrollChanged() {
                    try {
                        int scrollY = parentScrollView.getScrollY();
                        if (recyclerView.getLayoutManager().findViewByPosition(0) != null) {
                            if (isScrolled) {
                                // Log.d("bn", "crashinvestigation parentScrollView onScrollChange");
                                correctPosition(false);
                            }
                        }
                        // Log.d("bn", "crashinvestigation parentScrollView after 1");
                        isScrolled = false;

                        float onScrollChangedValue = parentScrollView.getMaxScrollAmount();
                        // Log.d("BN", "onScrollChangedValue view.scrollY():" + scrollY);
                        // Log.d("BN", "onScrollChangedValue view.getMaxScrollAmount():" +
                        // onScrollChangedValue);
                        float value = (float) scrollY / parentScrollView.getMaxScrollAmount();
                        if (value >= 1) {
                            value = 1;
                        }
                        float alpha = (float) (1 - value);
                        if (alpha < 1f) {
                            imageCreditLayout.setAlpha(alpha);
                        }
                        // Log.d("bn", "crashinvestigation parentScrollView /after 2");

                        // Log.d("bn",
                        //         "parentScrollViewObserver is alive:"
                        //                 + parentScrollViewObserver.isAlive());
                        Log.d("bn", "settingsBarinvestigation "+ settingsBar);
                        if (settingsBar != null
                                && settingsBar.getVisibility() == View.VISIBLE) {
                            if (value > 0.4 && settingsBar.getAlpha() <= 1f) {
                                settingsBar.setAlpha((float) (value + 0.5));
                            } else if (value < 0.4 && settingsBar.getAlpha() > 0f) {
                                settingsBar.setAlpha((float) (value - 0.2));
                            }
                            if (settingsBar.getAlpha() >= 1) {
                                settingsBarIsClickable = true;
                                LinearLayout.LayoutParams imageCreditLayoutParams =
                                    (LinearLayout.LayoutParams) imageCreditLayout.getLayoutParams();
                                // Log.d("bn", "imageCreditLayoutposition parentviewscroll reached top height" +imageCreditLayoutParams.height );
                                // Log.d("bn", "imageCreditLayoutposition imageCreditLayout top:" + imageCreditLayout.getTop() + " y:" +imageCreditLayout.getY() );
                                // Log.d("bn", "imageCreditLayoutposition settingsBar top:" + settingsBar.getTop() + " y:" +settingsBar.getY() );
                                // Log.d("bn", "imageCreditLayoutposition recyclerView top:" + recyclerView.getTop() + " y:" +recyclerView.getY() );

                                // recyclerView.setY(settingsBar.getY());
                                // imageCreditLayout.setVisibility(View.INVISIBLE);
                                // if (imageCreditLayoutParams.height > 1) {
                                    // Log.d("bn", "reached top setting small height");
                                    // imageCreditLayoutParams.height = 1;
                                    // imageCreditLayout.setLayoutParams(imageCreditLayoutParams);
                                // }
                            } else {
                                settingsBarIsClickable = false;
                                // Log.d("bn", "reached scrolled down");
                                // settingsBar.setVisibility(View.GONE);
                                // imageCreditLayout.setVisibility(View.VISIBLE);
                            }
                            // Log.d("BN",
                            //         "settings bar alpha: " + settingsBar.getAlpha()
                            //                 + "isClickable:" + settingsBarIsClickable);
                        }
                        // Log.d("bn", "crashinvestigation parentSc//rollView after 3");
                    } catch (Exception e) {
                        Log.e("bn",
                                "Exception crashinvestigation parentScrollViewObserver e:" + e);
                    }
                }
            });

        parentScrollViewObserver.addOnGlobalLayoutListener(
            new ViewTreeObserver.OnGlobalLayoutListener() {
                @Override
                public void onGlobalLayout() {
                    try {
                        // Log.d("bn", "newcontentchecks addOnGlobalLayoutListener settingsBar:"+settingsBar + " newContentButton: "+ newContentButton);
                        if (settingsBar != null) {
                            if (!isScrolled) {
                                settingsBar.setAlpha(0f);
                            }

                            ImageView newsSettingsButton = (ImageView) settingsBar.findViewById(
                                    R.id.news_settings_button);
                            ViewTreeObserver.OnGlobalLayoutListener listener = this;

                            newsSettingsButton.setOnClickListener(new View.OnClickListener() {
                                @Override
                                public void onClick(View v) {
                                    if (settingsBarIsClickable) {
                                        SettingsLauncher settingsLauncher =
                                                new SettingsLauncherImpl();
                                        settingsLauncher.launchSettingsActivity(
                                                getContext(), BraveNewsPreferences.class);
                                        parentScrollView.getViewTreeObserver()
                                                .removeOnGlobalLayoutListener(listener);
                                    }
                                }
                            });
                        }

                        if (newContentButton != null) {
                            Log.d("bn", "newContentButtonclick 1 :"+newContentButton);
                            ProgressBar loadingSpinner = (ProgressBar) newContentButton.findViewById(R.id.new_content_loading_spinner);
                            TextView newContentButtonText = (TextView) newContentButton.findViewById(R.id.new_content_button_text);
                            newContentButton.setOnClickListener(new View.OnClickListener() {
                                @Override
                                public void onClick(View v) {
                                    Log.d("bn", "newContentButtonclick loadingSpinner :"+loadingSpinner+ " newContentButtonText:"+newContentButtonText);
                                    Log.d("bn", "newContentButtonclick before loadingSpinner :"+loadingSpinner.getVisibility()+ " newContentButtonText:"+newContentButtonText.getVisibility());
  

                                    mActivity.runOnUiThread(new Runnable() {
                                        @Override
                                        public void run() {
                                            ((TextView) newContentButton.findViewById(R.id.new_content_button_text)).setVisibility(View.INVISIBLE);
                                            ((ProgressBar) newContentButton.findViewById(R.id.new_content_loading_spinner)).setVisibility(View.VISIBLE);
                                        }
                                    });

                                    Log.d("bn", "newContentButtonclick during loadingSpinner :"+loadingSpinner.getVisibility()+ " newContentButtonText:"+newContentButtonText.getVisibility());


                                    try {
                                        Thread.sleep(1000);
                                    } catch (InterruptedException e) {
                                        e.printStackTrace();
                                    }

                                    newContentButton.setClickable(false);
                                    SharedPreferencesManager.getInstance().writeBoolean(BravePreferenceKeys.BRAVE_NEWS_CHANGE_SOURCE, false);
                                    refreshFeed();

                                    mActivity.runOnUiThread(new Runnable() {
                                        @Override
                                        public void run() {
                                            ((TextView) newContentButton.findViewById(R.id.new_content_button_text)).setVisibility(View.VISIBLE);
                                            ((ProgressBar) newContentButton.findViewById(R.id.new_content_loading_spinner)).setVisibility(View.GONE);
                                            newContentButton.setClickable(true);
                                            newContentButton.setVisibility(View.INVISIBLE);
                                        }
                                    });

                                    Log.d("bn", "newContentButtonclick after loadingSpinner :"+loadingSpinner.getVisibility()+ " newContentButtonText:"+newContentButtonText.getVisibility());
                                }
                            });
                        }

                    } catch (Exception e) {
                        Log.e("bn",
                                "Exception  addOnGlobalLayoutListener e: "
                                        + e);
                    }
                }
            });

        RecyclerView.LayoutManager manager = recyclerView.getLayoutManager();
        if(manager instanceof LinearLayoutManager) {     
            LinearLayoutManager linearLayoutManager = (LinearLayoutManager) manager;
            firstVisiblCard = linearLayoutManager.findFirstVisibleItemPosition();
            // currentFirstVisible = 0;
            recyclerView.addOnScrollListener(new RecyclerView.OnScrollListener() {
                private int lastFirstVisibleItem;
                @Override
                public void onScrollStateChanged(@NonNull RecyclerView recyclerView, int newState) {
                    super.onScrollStateChanged(recyclerView, newState);

                    int offset = recyclerView.computeVerticalScrollOffset();

                    int firstCompletelyVisibleItemPosition = linearLayoutManager.findFirstCompletelyVisibleItemPosition(); 

                    if (newState == RecyclerView.SCROLL_STATE_DRAGGING) {
                        endCardViewTime = System.currentTimeMillis();
                        long timeDiff = endCardViewTime - startCardViewTime;
                        Log.d("bn",
                                "prevScrollPosition set timeDiff:" + timeDiff + "uuid:" + uuid + "cardType:"
                                        + cardType + "creativeInstanceId:" + creativeInstanceId + " offset: " + offset);
                        // if viewed for more than 100 ms send the event
                        if (timeDiff > 100) {
                            // BraveActivity.getBraveActivity().setNewsFeedScrollPosition(firstCompletelyVisibleItemPosition);
                            if (firstCompletelyVisibleItemPosition > 0){                            
                                SharedPreferencesManager.getInstance().writeInt(Integer.toString(BraveActivity.getBraveActivity().getActivityTab().getId()) , firstCompletelyVisibleItemPosition);
                                Log.d("bn", "tabmanagement set position: tab-"+Integer.toString(BraveActivity.getBraveActivity().getActivityTab().getId()) +" firstCompletelyVisibleItemPosition: " +firstCompletelyVisibleItemPosition);
                                Log.d("bn", "testviewedcards no. set:"+SharedPreferencesManager.getInstance().readInt("viewedNewsCardsCount_"+BraveActivity.getBraveActivity().getActivityTab().getId()));
                            }
                            Log.d("bn", "testviewedcards viewedNewsCardsCount:"+viewedNewsCardsCount + " firstCompletelyVisibleItemPosition:"+firstCompletelyVisibleItemPosition);
                            // Log.d("bn", "testviewedcards scrolldown currentFirstVisible:"+currentFirstVisible+" firstVisiblCard:"+firstVisiblCard);
                            //increment only for new cards seen (i.e. only when scrolling down, not when scrolling back up)
                            
                            // if (currentFirstVisible < firstVisiblCard) {
                                //scrolling down && %4 and  send event
                                
                            // }
                            // if (viewedNewsCardsCount >= SharedPreferencesManager.getInstance().readInt(BravePreferenceKeys.BRAVE_NEWS_CARDS_VIEWED)){
                            //     viewedNewsCardsCount+=firstCompletelyVisibleItemPosition;
                            // }
                            // Promotion card viewed events
                            
                            if (visibleCard != null) {
                                // logFeedItem(visibleCard, "!!!! sent card " + i + " :" );
                                    // if (! newsItemsFeedCard.get(itemPosition).isViewStatSent()) {
                                Log.d("bn", "testviewedcards1 before visibleCard: " + visibleCard.getCardType() + " isviewstatsent: " + visibleCard.isViewStatSent() + " uuid:" + uuid + " creativeInstanceId: " + creativeInstanceId);
                                if (!visibleCard.isViewStatSent()) {

                                    if (cardType.equals("promo")) {
                                        if (!uuid.equals("") && !creativeInstanceId.equals("")) {
                                            Log.d("bn",
                                            "testviewedcards1 newsEvents !!!! sent " + cardType + " uuid:" + uuid
                                                    + " creativeInstanceId:" + creativeInstanceId);
                                            mBraveNewsController.onPromotedItemView(
                                                    uuid, creativeInstanceId);
                                        }
                                    } else if (cardType.equals("displayad")) {
                                        if (uuid != null && creativeInstanceId != null){                                        
                                            if (!uuid.equals("") && !creativeInstanceId.equals("")) {
                                                Log.d("bn",
                                                "testviewedcards1 newsEvents !!!! sent " + cardType + " uuid:" + uuid
                                                        + " creativeInstanceId:" + creativeInstanceId);
                                                mBraveNewsController.onDisplayAdView(
                                                        uuid, creativeInstanceId);
                                            }
                                        }
                                    } else {
                                        viewedNewsCardsCount ++;
                                        Log.d("bn", "RecyclerViewscrolled: scrolled  testviewedcards1  viewedNewsCardsCount " + viewedNewsCardsCount);
                                        SharedPreferencesManager.getInstance().writeInt(
                                            "viewedNewsCardsCount_"+BraveActivity.getBraveActivity().getActivityTab().getId(), viewedNewsCardsCount);

                                        if (viewedNewsCardsCount % 4 == 0 && viewedNewsCardsCount > 0) {
                                            Log.d("bn", "RecyclerViewscrolled: scrolled  testviewedcards1 newsEvents !!!! viewedNewsCardsCount sent " + viewedNewsCardsCount);
                                            mBraveNewsController.onSessionCardViewsCountChanged(
                                                    (short) viewedNewsCardsCount);
                                        }
                                    }
                                    visibleCard.setViewStatSent(true);
                                    Log.d("bn", "testviewedcards1 after visibleCard: " + visibleCard.getCardType() + " isviewstatsent: " + visibleCard.isViewStatSent());                                    
                                    //newsItemsFeedCard.get(itemPosition).setViewStatSent(true);
                                }
                            }
                        }
                    }

                    if (newState == RecyclerView.SCROLL_STATE_IDLE) {

                        startCardViewTime = System.currentTimeMillis();
                        int firstVisibleItemPosition =
                                linearLayoutManager.findFirstVisibleItemPosition();

                        int lastVisibleItemPosition = linearLayoutManager.findLastVisibleItemPosition();

                        if(y > 0){
                            y=0;
                            int newFirstCompletelyVisibleItemPosition = linearLayoutManager.findFirstCompletelyVisibleItemPosition(); 

                            // if (viewedNewsCardsCount == 0 || viewedNewsCardsCount <= firstCompletelyVisibleItemPosition){
                            //     viewedNewsCardsCount = firstCompletelyVisibleItemPosition;

                            //     SharedPreferencesManager.getInstance().writeInt(
                            //         BravePreferenceKeys.BRAVE_NEWS_CARDS_VIEWED, viewedNewsCardsCount);
                            //     if (viewedNewsCardsCount % 4 == 0 && viewedNewsCardsCount > 0) {
                            //         Log.d("bn", "RecyclerViewscrolled: scrolled  testviewedcards newsEvents !!!! viewedNewsCardsCount sent " + viewedNewsCardsCount);
                            //         mBraveNewsController.onSessionCardViewsCountChanged(
                            //                 (short) viewedNewsCardsCount);
                            //     }
                            // }

                        }


                        feedHash = SharedPreferencesManager.getInstance().readString(BravePreferenceKeys.BRAVE_NEWS_FEED_HASH, "");
                        Log.d("bn", "newcontentchecks feedHash:" +feedHash);
                        mBraveNewsController.isFeedUpdateAvailable(feedHash, isNewsFeedAvailable -> {
                            Log.d("bn", "newcontentchecks isFeedUpdateAvailable :" + isFeedUpdateAvailable + " feedHash:" +feedHash);
                            if (isNewsFeedAvailable) {
                                if (newContentButton != null) {
                                    newContentButton.setVisibility(View.VISIBLE);
                                } 
                            }
                        });

                        for (int viewPosition = firstVisibleItemPosition;
                                viewPosition <= lastVisibleItemPosition; viewPosition++) {
                            View itemView = manager.findViewByPosition(viewPosition);
                            int visiblePercentage = (int) getVisibleHeightPercentage(itemView);
                            // Log.d("bn", "onScrolled SCROLL_STATE_IDLE offset:" + offset);
                            if (visiblePercentage >= MINIMUM_VISIBLE_HEIGHT_THRESHOLD) {
                                visibleCard = newsItemsFeedCard.get(viewPosition);
                                Log.d("bn", "testviewedcards1 before visibleCard idle position: "+viewPosition);
                                // get params for view PROMOTED_ARTICLE
                                if (visibleCard.getCardType() == CardType.PROMOTED_ARTICLE) {
                                    itemPosition = viewPosition;
                                    creativeInstanceId = braveNewsUtils.getPromotionIdItem(visibleCard);
                                    // Log.d("bn",
                                    //         "newsEvents visiblePercentage PROMOTED_ARTICLE" + visiblePercentage
                                    //                 + " creativeInstanceId:" + creativeInstanceId);
                                    uuid = visibleCard.getUuid();
                                    cardType = "promo";
                                    //
                                }                                
                                // get params for view DISPLAY_AD
                                if (visibleCard.getCardType() == CardType.DISPLAY_AD) {
                                    itemPosition = viewPosition;
                                    DisplayAd currentDisplayAd = NTPUtil.getCurrentDisplayAd();
                                    if (currentDisplayAd != null){
                                        Log.d("bn", "newsEvents visiblePercentage DISPLAY_AD: title: "+currentDisplayAd.title); 
                                        Log.d("bn", "newsEvents visiblePercentage DISPLAY_AD: id: "+currentDisplayAd.uuid); 
                                        Log.d("bn", "newsEvents visiblePercentage DISPLAY_AD: creativeInstanceId: "+currentDisplayAd.creativeInstanceId); 

                                        creativeInstanceId = currentDisplayAd != null ? currentDisplayAd.creativeInstanceId : "";
                                        uuid = currentDisplayAd != null ? currentDisplayAd.uuid : "";
                                    
                                        Log.d("bn",
                                                "newsEvents visiblePercentage DISPLAY_AD" + visiblePercentage
                                                        + " creativeInstanceId:" + creativeInstanceId);
                                        cardType = "displayad";
                                    }
                                }
                            }
                        }
                    }
                }

                @Override
                public void onScrolled(@NonNull RecyclerView recyclerView, int dx, int dy) {
                    super.onScrolled(recyclerView, dx, dy);
                    y=dy;
                    try {
                        // Log.d("bn", "crashinvestigation onScrolled");
                        int offset = recyclerView.computeVerticalScrollOffset();
                        int firstVisibleItemPosition =
                                linearLayoutManager.findFirstVisibleItemPosition();
                        int visibleItemCount =
                                linearLayoutManager.getChildCount();



                        int currFirstPos = linearLayoutManager.findFirstCompletelyVisibleItemPosition();
                        int currLastPos = linearLayoutManager.findLastCompletelyVisibleItemPosition();

                        // totalItemCount = linearLayoutManager.getItemCount();



                        int currentlyLoaded = visibleItemCount + firstVisibleItemPosition;
                        int page = (int) Math.floor(currentlyLoaded / ITEMS_PER_PAGE);


                        if (dy > 0) {
                            // scroll down
                            Log.d("bn", "RecyclerViewscrolled: scroll dy down!");
                        } else {
                            //scroll up
                            Log.d("bn", "RecyclerViewscrolled: scroll dy up!");
                        }

                        int currentFirstVisible = linearLayoutManager.findFirstVisibleItemPosition();
                        Log.i("bn", "RecyclerViewscrolled: scroll currentFirstVisible: " +currentFirstVisible +
                             " firstVisiblCard:"+ firstVisiblCard);  

                        if(currentFirstVisible > firstVisiblCard){
                            Log.i("bn", "RecyclerViewscrolled: scroll up!");
                        } else if(currentFirstVisible <= firstVisiblCard){
                            if(oldFirstPos == -1){
                                totalItemsViewed += currLastPos - currFirstPos + 1;
                            }else{
                                // if(dy > 0){
                                //     totalItemsViewed += Math.abs(currLastPos - oldLastPos);
                                // }else{
                                //     totalItemsViewed -= Math.abs(oldLastPos - currLastPos);
                                // }
                            }
                            oldLastPos = currLastPos;
                            oldFirstPos = currFirstPos;
                            Log.i("bn", "RecyclerViewscrolled: scroll down! incrementing: " +totalItemsViewed);  
                            // totalItemsViewed += currLastPos - currFirstPos + 1;
                        }

                        // Log.d("bn", "RecyclerViewscrolled : oldLastPos:"+oldLastPos + " oldFirstPos: "+ oldFirstPos+" dy:"+dy);


                        firstVisiblCard = currentFirstVisible;

                        int thrashold = 6; //(page*ITEMS_PER_PAGE) - 5;
                        // Log.d("BN", "loadMoreItems currentlyLoaded:" + currentlyLoaded + " page:" +
                        // page + " thrashold:" + thrashold);

                        if (firstVisibleItemPosition + thrashold == (page + 1) * ITEMS_PER_PAGE) {
                            // page++;
                            Log.d("BN", "RecyclerViewscrolled page:" + page);
                            // loadMoreItems(page);
                        }

                        parentScrollView.post(new Runnable() {
                            @Override
                            public void run() {
                                // Log.d("BN",
                                //         "onScrolled scroll to:" + offset + " positionL:"
                                //                 + parentScrollView.getVerticalScrollbarPosition());
                                try {
                                    parentScrollView.scrollBy(0, offset + 20);

                                } catch (Exception e) {
                                    Log.e("bn","Exception crashinvestigation recyclerView addOnScrollListener e:"
                                                    + e);
                                }
                            }
                        });

                    } catch (Exception e) {
                        Log.d("bn", "crashinvestigation Exception onScrolled:" + e);
                    }
                }
            });
        }

        optinClose.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Log.d("BN", "close_optin");

                SharedPreferences.Editor sharedPreferencesEditor = sharedPreferences.edit();
                sharedPreferencesEditor.putBoolean(BraveNewsPreferences.PREF_SHOW_OPTIN, false);
                sharedPreferencesEditor.apply();

                if (optinLayout != null) {
                    optinLayout.setVisibility(View.GONE);
                }
                correctPosition(false);
                parentScrollView.scrollTo(0, 0);
                imageCreditLayout.setAlpha(1.0f);
            }
        });

        optinLearnMore.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Log.d("BN", "optin_learnmorex");
                Intent browserIntent =
                        new Intent(Intent.ACTION_VIEW, Uri.parse("http://www.brave.com"));
                browserIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                mActivity.startActivity(browserIntent);
            }
        });

        optinButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {

                // loadingView.setVisibility(View.VISIBLE);
                optinButton.setClickable(false);
                optinText.setVisibility(View.INVISIBLE);
                loadingView.setVisibility(View.VISIBLE);

                SharedPreferences.Editor sharedPreferencesEditor = sharedPreferences.edit();
                sharedPreferencesEditor.putBoolean(BraveNewsPreferences.PREF_SHOW_OPTIN, false);
                sharedPreferencesEditor.apply();
                BravePrefServiceBridge.getInstance().setNewsOptIn(true);
                BravePrefServiceBridge.getInstance().setShowNews(true);
                if (BraveActivity.getBraveActivity() != null){
                    BraveActivity.getBraveActivity().inflateNewsSettingsBar();
                    settingsBar = (LinearLayout) compositorView.findViewById(R.id.news_settings_bar);
                }

                getFeed();
                /*
                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        Log.d("bravenews", "getting feed...");
                        
                        if (mBraveNewsController != null) {
                            mBraveNewsController.getFeed((feed) -> {
                                // Log.d("bn", "getfeed result: " + result);
                                Log.d("bn", "getfeed feed: " + feed);
                                Log.d("bn", "getfeed feed hash: " + feed.hash);
                                // Log.d("bn", "getfeed feed featured_article: " + feed.featured_article);
                                // Log.d("bn", "getfeed feed featured_article.data: " + feed.featured_article.data);
                                // Log.d("bn", "getfeed feed featured_article.data.category_name: " + feed.featured_article.data.category_name);
                            });
                        } else {
                            Log.d("bn", " getfeed mBraveNewsController is null ");
                        }
                        getFeed();
                        new Handler(Looper.getMainLooper()).postDelayed(new Runnable() {
                            @Override
                            public void run() {
                                Log.d("BN", "optin click after");

                                loadingView.setVisibility(View.GONE);
                                optinLayout.setVisibility(View.GONE);
                                parentLayout.removeView(optinLayout);

                                container.setVisibility(View.VISIBLE);
                                recyclerView.setVisibility(View.VISIBLE);

                                // nestedScrollView.setVisibility(View.VISIBLE);
                                // preferences.setOptIn(true);

                                // adapter.notifyDataSetChanged();
                                // adapterFeed.notifyDataSetChanged();
                                adapterFeedCard.notifyDataSetChanged();

                                parentScrollView.scrollTo(0, 0);
                                // parentScrollView.fullScroll(ScrollView.FOCUS_UP);

                                isScrolled = true;
                                Log.d("BN", "optin click after recycler y0:" + recyclerView.getY());

                                if (recyclerView.getLayoutManager().findViewByPosition(0) != null) {
                                    Log.d("BN",
                                            "optin click after y0:"
                                                    + recyclerView.getLayoutManager()
                                                              .findViewByPosition(0)
                                                              .getY());
                                }
                            }
                        }, 1000);
                    }
                }).start();
                */
            }
        });
    }

    // private void analyzeAndAddViewData(int firstVisibleItemPosition, int lastVisibleItemPosition)
    // {

    //     for (int viewPosition = firstVisibleItemPosition; viewPosition <=
    //     lastVisibleItemPosition; viewPosition++) {

    //         Log.i("View being considered", String.valueOf(viewPosition));

    //         // Get the view from its position.
    //         View itemView = recyclerView.getLayoutManager().findViewByPosition(viewPosition);

    //         // Check if the visibility of the view is more than or equal
    //         // to the threshold provided. If it falls under the desired limit,
    //         // add it to the tracking data.
    //         if (
    //           getVisibleHeightPercentage(itemView) >=
    //             minimumVisibleHeightThreshold) {
    //             viewsViewed.add(viewPosition);
    //         }
    //     }
    // }

    protected boolean handleBackPressed() {
        Log.d("bn", "backmanager handleBackPressed to BraveActivity");
        return true;
    }

    private double getVisibleHeightPercentage(View view) {
        Rect itemRect = new Rect();
        double viewVisibleHeightPercentage = 0;
        if (view != null) {
            view.getLocalVisibleRect(itemRect);

            // Find the height of the item.
            double visibleHeight = itemRect.height();
            double height = view.getMeasuredHeight();

            Log.i("Visible Height", String.valueOf(visibleHeight));
            Log.i("Measured Height", String.valueOf(height));

            viewVisibleHeightPercentage = ((visibleHeight / height) * 100);

            Log.i("Percentage visible", String.valueOf(viewVisibleHeightPercentage));
        }

        return viewVisibleHeightPercentage;
    }

    private void loadMoreItems(int page) {
        int startIndex = page * ITEMS_PER_PAGE;
        int endIndex = startIndex + ITEMS_PER_PAGE;
        Log.d("bn", "loadMoreItems indexing page:"+page);
        Log.d("bn", "loadMoreItems indexing startIndex:"+startIndex);
        Log.d("bn", "loadMoreItems indexing endIndex:"+endIndex);
        // newsRecyclerItems
        // for (FeedItemsCard feedItemsCard : newsItemsFeedCard){

        Log.d("BN", "loadMoreItems indexing process before: newsRecyclerItems!!: "+newsRecyclerItems.size());
        // for (FeedItemsCard feedItemsCard : newsRecyclerItems){
        //     logFeedItem(feedItemsCard, "loadMoreItems indexing process before: " );
        // }
        for (int i = startIndex; i < endIndex; i ++){    
            Log.d("bn", "loadMoreItems indexing:"+i);
            FeedItemsCard feedItemsCard = newsItemsFeedCard.get(i);
            // if (feedItemsCard.getFeedItems() != null){
                // if (startIndex < endIndex){  
                    // Log.d("BN", "loadMoreItems indexing cardtype: "+feedItemsCard.getCardType());    
                    
                    if (feedItemsCard.getCardType() != CardType.DISPLAY_AD){     
                        for (FeedItemCard itemCard : feedItemsCard.getFeedItems()){
                            FeedItem item = itemCard.getFeedItem();

                            FeedItemMetadata itemMetaData = new FeedItemMetadata();
                            switch(item.which()){
                                case FeedItem.Tag.Article:
                                    Article article = item.getArticle();
                                    itemMetaData = article.data;
                                    break;
                                case FeedItem.Tag.PromotedArticle:
                                    PromotedArticle promotedArticle = item.getPromotedArticle();
                                    itemMetaData = promotedArticle.data;
                                    break;                                            
                                case FeedItem.Tag.Deal:
                                    Deal deal = item.getDeal();
                                    itemMetaData = deal.data;
                                    break;
                            }
                            Url itemImageUrl = getImage(itemMetaData);
                            mBraveNewsController.getImageData(itemImageUrl, imageData -> {
                                if (imageData != null){
                                    itemCard.setImageByte(imageData);
                                }
                            });
                            // newsRecyclerItems.setFeedItems(feedItemsCard.getFeedItems());
                            
                        }
                    }              
                    
                    // newsRecyclerItems.add(feedItemsCard);
                    // final int addIndex = i;
                    // recyclerView.post(new Runnable() {
                    //     public void run() {
                    //         adapterFeedCard.notifyItemInserted(addIndex);
                    //     }
                    // });

                // }
            // } 
            // startIndex ++;
        }
        
        Log.d("BN", "loadMoreItems indexing process after: newsRecyclerItems!!: "+newsRecyclerItems.size());
        int newsRecyclerIndex = 0;
        for (FeedItemsCard feedItemsCard : newsRecyclerItems){
            Log.d("BN", "loadMoreItems indexing process after: newsRecyclerIndex"+newsRecyclerIndex);
            if (newsRecyclerIndex < 50) {
                logFeedItem(feedItemsCard, "loadMoreItems indexing process after: ");
            }
            newsRecyclerIndex ++;
        }

        // recyclerView.post(new Runnable() {
        //     public void run() {
        //         adapterFeedCard.notifyDataSetChanged();
        //     }
        // });
    }


    private void setFeed(){
        Log.d("BN", "processFeed click after newsItemsFeedCard: "+newsItemsFeedCard.size());

        int feedIndex = 0;
        for (FeedItemsCard feedItemsCard : newsItemsFeedCard){
            Log.d("BN", "processFeed click after cardtype: "+feedItemsCard.getCardType());
                logFeedItem(feedItemsCard, "processFeed click after " + feedIndex + " : ");
                feedIndex++;
        }

        feedSpinner.setVisibility(View.GONE);
        optinLayout.setVisibility(View.GONE);

        container.setVisibility(View.VISIBLE);
        recyclerView.setVisibility(View.VISIBLE);

        try {
            parentScrollView.scrollTo(0, 0);
        } catch (Exception e) {
            Log.e("bn", "Exception crashinvestigation processfeed e:" + e);
        }

        isScrolled = true;
    }

    private void processFeed(){
        Log.d("BN", "processFeed click after newsItemsFeedCard: "+newsItemsFeedCard.size());

        int feedIndex = 0;
        for (FeedItemsCard feedItemsCard : newsItemsFeedCard){
            Log.d("BN", "processFeed click after cardtype: "+feedItemsCard.getCardType());
                logFeedItem(feedItemsCard, "processFeed click after " + feedIndex + " : ");
                feedIndex++;
        }

        feedSpinner.setVisibility(View.GONE);
        optinLayout.setVisibility(View.GONE);

        container.setVisibility(View.VISIBLE);
        recyclerView.setVisibility(View.VISIBLE);

        adapterFeedCard.notifyDataSetChanged();

        try {
            parentScrollView.scrollTo(0, 0);
        } catch (Exception e) {
            Log.e("bn", "Exception crashinvestigation processfeed e:" + e);
        }

        isScrolled = true;
    }

    @Override
    public void initialize(NewTabPageManager manager, Activity activity,
            TileGroup.Delegate tileGroupDelegate, boolean searchProviderHasLogo,
            boolean searchProviderIsGoogle, ScrollDelegate scrollDelegate,
            ContextMenuManager contextMenuManager, UiConfig uiConfig, Supplier<Tab> tabProvider,
            ActivityLifecycleDispatcher lifecycleDispatcher, NewTabPageUma uma, boolean isIncognito,
            WindowAndroid windowAndroid) {
        super.initialize(manager, activity, tileGroupDelegate, searchProviderHasLogo,
                searchProviderIsGoogle, scrollDelegate, contextMenuManager, uiConfig, tabProvider,
                lifecycleDispatcher, uma, isIncognito, windowAndroid);

        assert (activity instanceof BraveActivity);
        mActivity = activity;
        Log.d("bn", "persistencetest feed loaded: added mActivity: " + mActivity + " mBraveNewsController: "+mBraveNewsController);     
        ((BraveActivity) mActivity).dismissShieldsTooltip();
        CompositorViewHolder compositorView = findViewById(R.id.compositor_view_holder);
         Log.d("BN", "lifecycle init settingsBar:" + settingsBar);
    }

    private void showNTPImage(NTPImage ntpImage) {
        Display display = mActivity.getWindowManager().getDefaultDisplay();
        Point size = new Point();
        display.getSize(size);
        NTPUtil.updateOrientedUI(mActivity, this, size, ntpImage);
        ImageView mSponsoredLogo = (ImageView) findViewById(R.id.sponsored_logo);
        FloatingActionButton mSuperReferralLogo = (FloatingActionButton) findViewById(R.id.super_referral_logo);
        TextView mCreditText = (TextView) findViewById(R.id.credit_text);
        LinearLayout optinLayout = (LinearLayout) findViewById(R.id.optin_layout_id);
        ntpImageGlobal = ntpImage;
        if (ntpImage instanceof Wallpaper
                && NTPUtil.isReferralEnabled()
                && Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            Log.d("BN", "bgimage if");
            Log.d("bn", "bgimagestep 0");
            setBackgroundImage(ntpImage);
            mSuperReferralLogo.setVisibility(View.VISIBLE);
            mCreditText.setVisibility(View.GONE);
            int floatingButtonIcon = R.drawable.ic_qr_code;
            mSuperReferralLogo.setImageResource(floatingButtonIcon);
            int floatingButtonIconColor =
                    GlobalNightModeStateProviderHolder.getInstance().isInNightMode()
                    ? android.R.color.white
                    : android.R.color.black;
            ImageViewCompat.setImageTintList(
                    mSuperReferralLogo, ColorStateList.valueOf(floatingButtonIconColor));
            mSuperReferralLogo.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View view) {
                    QRCodeShareDialogFragment mQRCodeShareDialogFragment =
                            new QRCodeShareDialogFragment();
                    mQRCodeShareDialogFragment.setQRCodeText(
                            BRAVE_REF_URL + mNTPBackgroundImagesBridge.getSuperReferralCode());
                    mQRCodeShareDialogFragment.show(
                            ((BraveActivity) mActivity).getSupportFragmentManager(),
                            "QRCodeShareDialogFragment");
                }
            });
        } else if (UserPrefs.get(Profile.getLastUsedRegularProfile()).getBoolean(
                       BravePref.NEW_TAB_PAGE_SHOW_BACKGROUND_IMAGE)
                   && sponsoredTab != null
                   && NTPUtil.shouldEnableNTPFeature()) {
            Log.d("BN", "bgimage else if");
            setBackgroundImage(ntpImage);
            // optinLayout.setVisibility(View.VISIBLE);
            if (ntpImage instanceof BackgroundImage) {
                BackgroundImage backgroundImage = (BackgroundImage) ntpImage;
                mSponsoredLogo.setVisibility(View.GONE);
                mSuperReferralLogo.setVisibility(View.GONE);

                if (backgroundImage.getImageCredit() != null) {
                    Log.d("bn", "bgimagestep 1");
                    String imageCreditStr = String.format(getResources().getString(R.string.photo_by, backgroundImage.getImageCredit().getName()));

                    SpannableStringBuilder spannableString = new SpannableStringBuilder(imageCreditStr);
                    spannableString.setSpan(
                        new android.text.style.StyleSpan(android.graphics.Typeface.BOLD),
                        ((imageCreditStr.length() - 1)
                         - (backgroundImage.getImageCredit().getName().length() - 1)),
                        imageCreditStr.length(), Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);

                    mCreditText.setText(spannableString);
                    mCreditText.setVisibility(View.VISIBLE);

                    mCreditText.setOnClickListener(new View.OnClickListener() {
                        @Override
                        public void onClick(View view) {
                            if (backgroundImage.getImageCredit() != null) {
                                TabUtils.openUrlInSameTab(
                                        backgroundImage.getImageCredit().getUrl());
                            }
                        }
                    });
                } else {
                    Log.d("bn", "bgimagestep 2");
                }
            } else {
                Log.d("bn", "bgimagestep 3");
            }
        } else {
            Log.d("BN", "bgimage else");
        }
    }

    private void setBackgroundImage(NTPImage ntpImage) {
        bgImageView = (ImageView) findViewById(R.id.bg_image_view);
        // ntpLayout = (BraveNewTabPageLayout) findViewById(R.id.ntp_content);
        // bgImageView.setScaleType(ImageView.ScaleType.CENTER_INSIDE);
        Log.d("BN", "setting bgImageView:" + ntpImage);       
        // Log.d("BN", "setting bgImageView:" + ntpImage);

        ViewTreeObserver observer = bgImageView.getViewTreeObserver();
        observer.addOnGlobalLayoutListener(new ViewTreeObserver.OnGlobalLayoutListener() {
            @Override
            public void onGlobalLayout() {
                mWorkerTask = new FetchWallpaperWorkerTask(ntpImage, bgImageView.getMeasuredWidth(),
                        bgImageView.getMeasuredHeight(), wallpaperRetrievedCallback);
                mWorkerTask.executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR);

                bgImageView.getViewTreeObserver().removeOnGlobalLayoutListener(this);
            }
        });
    }

    private void checkForNonDisruptiveBanner(NTPImage ntpImage) {
        int brOption = NTPUtil.checkForNonDisruptiveBanner(ntpImage, sponsoredTab);
        if (SponsoredImageUtil.BR_INVALID_OPTION != brOption && !NTPUtil.isReferralEnabled()
                && ((!BraveAdsNativeHelper.nativeIsBraveAdsEnabled(
                             Profile.getLastUsedRegularProfile())
                            && BraveRewardsHelper.shouldShowBraveRewardsOnboardingModal())
                        || BraveAdsNativeHelper.nativeIsBraveAdsEnabled(
                                Profile.getLastUsedRegularProfile()))) {
            NTPUtil.showNonDisruptiveBanner((BraveActivity) mActivity, this, brOption,
                                             sponsoredTab, newTabPageListener);
        }
    }

    private void checkAndShowNTPImage(boolean isReset) {
        NTPImage ntpImage = sponsoredTab.getTabNTPImage(isReset);
        Log.d("BN", "checking NTP");
        if (ntpImage == null) {
            Log.d("BN", "ntpImage null setting 1");
            sponsoredTab.setNTPImage(SponsoredImageUtil.getBackgroundImage());
        } else if (ntpImage instanceof Wallpaper) {
            Log.d("BN", "ntpImage not null setting 2");

            Wallpaper mWallpaper = (Wallpaper) ntpImage;
            if (mWallpaper == null) {
                sponsoredTab.setNTPImage(SponsoredImageUtil.getBackgroundImage());
            }
        }
        checkForNonDisruptiveBanner(ntpImage);
        showNTPImage(ntpImage);
    }

    private void initilizeSponsoredTab() {
        if (TabAttributes.from(getTab()).get(String.valueOf(getTabImpl().getId())) == null) {
            SponsoredTab mSponsoredTab = new SponsoredTab(mNTPBackgroundImagesBridge);
            TabAttributes.from(getTab()).set(String.valueOf(getTabImpl().getId()), mSponsoredTab);
        }
        sponsoredTab = TabAttributes.from(getTab()).get(String.valueOf((getTabImpl()).getId()));
        if (shouldShowSuperReferral()) mNTPBackgroundImagesBridge.getTopSites();
    }

    private NewTabPageListener newTabPageListener = new NewTabPageListener() {
        @Override
        public void updateInteractableFlag(boolean isBottomSheet) {
            isFromBottomSheet = isBottomSheet;
        }

        @Override
        public void updateNTPImage() {
            if (sponsoredTab == null) {
                initilizeSponsoredTab();
            }
            checkAndShowNTPImage(false);

            Log.d("bn", "updateNTPImage");
            parentScrollView = (ScrollView) ntpContent.getParent();
            Log.d("bn", "rootView:" + parentScrollView);
            ViewGroup rootView = (ViewGroup) parentScrollView.getParent();
            Log.d("bn", "rootView:" + rootView);
            CompositorViewHolder compositorView = (CompositorViewHolder) rootView.getParent();
            Log.d("bn", "settingsBarinvestigation newTabPageListener compositorView : " + compositorView);
            final int childCount = compositorView.getChildCount();
            Log.d("bn", "childCount:" + childCount);
            for (int i = 0; i < childCount; i++) {
                View v = compositorView.getChildAt(i);
                Log.d("bn", "child view :" + v);
            }
        }

        @Override
        public void updateTopSites(List<TopSite> topSites) {
            new AsyncTask<List<TopSiteTable>>() {
                @Override
                protected List<TopSiteTable> doInBackground() {
                    for (TopSite topSite : topSites) {
                        mDatabaseHelper.insertTopSite(topSite);
                    }
                    return mDatabaseHelper.getAllTopSites();
                }

                @Override
                protected void onPostExecute(List<TopSiteTable> topSites) {
                    assert ThreadUtils.runningOnUiThread();
                    if (isCancelled()) return;

                    loadTopSites(topSites);
                }
            }.executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR);
        }

    };

    private NTPBackgroundImagesBridge.NTPBackgroundImageServiceObserver mNTPBackgroundImageServiceObserver = new NTPBackgroundImagesBridge.NTPBackgroundImageServiceObserver() {
        @Override
        public void onUpdated() {
            if (NTPUtil.isReferralEnabled()) {
                checkAndShowNTPImage(true);
                if (shouldShowSuperReferral()) {
                    mNTPBackgroundImagesBridge.getTopSites();
                }
            }
        } 
    };

    private FetchWallpaperWorkerTask.WallpaperRetrievedCallback wallpaperRetrievedCallback = new FetchWallpaperWorkerTask.WallpaperRetrievedCallback() {
        @Override
        public void bgWallpaperRetrieved(Bitmap bgWallpaper) {
            Log.d("BN", "setting wallpaper:" + bgWallpaper);
            if (BraveActivity.getBraveActivity() != null) {
                BraveActivity.getBraveActivity().setBackground(bgWallpaper);
            }

            parentScrollView = (ScrollView) ntpContent.getParent();
            Log.d("bn", "rootView:" + parentScrollView);
            ViewGroup rootView = (ViewGroup) parentScrollView.getParent();
            Log.d("bn", "rootView:" + rootView);
            ViewGroup coordinator = (ViewGroup) rootView.getParent();
            ViewStub bottomControlsStub = (ViewStub) findViewById(R.id.bottom_controls_stub);
            if (bottomControlsStub != null) {
                Log.d("bn", "margintop callback bottomControlsStub:" + bottomControlsStub.getTop());
            }
            if (coordinator != null) {
                ViewGroup bottomBar = (ViewGroup) rootView.findViewById(R.id.bottom_controls);
                if (bottomBar != null) {
                    Log.d("bn", "margintop callback bottomBar:" + bottomBar.getTop());
                }
            }
            CompositorViewHolder compositorView = (CompositorViewHolder) rootView.getParent();
            Log.d("bn", "settingsBarinvestigation bgWallpaperRetrieved compositorView:" + compositorView);

            final int childCount = compositorView.getChildCount();
            Log.d("bn", "childCount:" + childCount);
            for (int index = 0; index < ((ViewGroup) compositorView).getChildCount(); index++) {
                View nextChild = ((ViewGroup) compositorView).getChildAt(index);
                Log.d("bn", "compositorViewchildren ntplayout nextchild before add:" + nextChild);
            }

            try {
                if (BraveActivity.getBraveActivity() != null 
                        && BraveActivity.getBraveActivity().getActivityTab() != null) {
                    if (UrlUtilities.isNTPUrl(
                                BraveActivity.getBraveActivity().getActivityTab().getUrl().getSpec())) {
                        if (compositorView.getChildAt(2).getId() == R.id.news_settings_bar) {
                            settingsBar = (LinearLayout) compositorView.getChildAt(2);
                            Log.d("bn", "fetched settings bar :" + settingsBar.getId());
                            Log.d("bn", "fetched settings bar :" + R.id.news_settings_bar);
                            Log.d("bn",
                                    "fetched settings bar :" + R.layout.brave_news_settings_bar_layout);
                            settingsBar.setVisibility(View.VISIBLE);
                            settingsBar.setAlpha(0f);
                        }

                        if (compositorView.getChildAt(3).getId() == R.id.new_content_layout_id) {
                            newContentButton = (RelativeLayout) compositorView.getChildAt(3);
                            // newContentButton.setVisibility(View.INVISIBLE);
                        }
                    }
                }
            } catch (Exception e) {
                Log.e("bn", "crashinvestigation exception fetched settings bar: " + e.getMessage());
            }
        }

        @Override
        public void logoRetrieved(Wallpaper mWallpaper, Bitmap logoWallpaper) {
            if (!NTPUtil.isReferralEnabled()) {
                FloatingActionButton mSuperReferralLogo = (FloatingActionButton) findViewById(R.id.super_referral_logo);
                mSuperReferralLogo.setVisibility(View.GONE);

                ImageView sponsoredLogo = (ImageView) findViewById(R.id.sponsored_logo);
                sponsoredLogo.setVisibility(View.VISIBLE);
                sponsoredLogo.setImageBitmap(logoWallpaper);
                sponsoredLogo.setOnClickListener(new View.OnClickListener() {
                    @Override
                    public void onClick(View view) {
                        if (mWallpaper.getLogoDestinationUrl() != null) {
                            TabUtils.openUrlInSameTab(mWallpaper.getLogoDestinationUrl());
                            mNTPBackgroundImagesBridge.wallpaperLogoClicked(mWallpaper);
                        }
                    }
                });
            }
        }
    };

    private void loadTopSites(List<TopSiteTable> topSites) {
        superReferralSitesLayout = new LinearLayout(mActivity);
        superReferralSitesLayout.setWeightSum(1f);
        superReferralSitesLayout.setOrientation(LinearLayout.HORIZONTAL);
        superReferralSitesLayout.setBackgroundColor(
                mActivity.getResources().getColor(R.color.topsite_bg_color));

        LayoutInflater inflater = (LayoutInflater) mActivity.getSystemService(Context.LAYOUT_INFLATER_SERVICE);

        for (TopSiteTable topSite : topSites) {
            final View view = inflater.inflate(R.layout.suggestions_tile_view, null);

            TextView tileViewTitleTv = view.findViewById(R.id.tile_view_title);
            tileViewTitleTv.setText(topSite.getName());
            tileViewTitleTv.setTextColor(getResources().getColor(android.R.color.black));

            ImageView iconIv = view.findViewById(R.id.tile_view_icon);
            if (NTPUtil.imageCache.get(topSite.getDestinationUrl()) == null) {
                NTPUtil.imageCache.put(topSite.getDestinationUrl(), new java.lang.ref.SoftReference(NTPUtil.getTopSiteBitmap(topSite.getImagePath())));
            }
            iconIv.setImageBitmap(NTPUtil.imageCache.get(topSite.getDestinationUrl()).get());
            iconIv.setBackgroundColor(mActivity.getResources().getColor(android.R.color.white));
            iconIv.setClickable(false);

            view.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View view) {
                    TabUtils.openUrlInSameTab(topSite.getDestinationUrl());
                }
            });

            view.setPadding(0, dpToPx(mActivity, 12), 0, 0);

            LinearLayout.LayoutParams layoutParams = new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.MATCH_PARENT);
            layoutParams.weight = 0.25f;
            layoutParams.gravity = Gravity.CENTER;
            view.setLayoutParams(layoutParams);
            view.setOnCreateContextMenuListener(new View.OnCreateContextMenuListener() {
                @Override
                public void onCreateContextMenu(ContextMenu menu, View v, ContextMenu.ContextMenuInfo menuInfo) {
                    menu.add(R.string.contextmenu_open_in_new_tab).setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
                        @Override
                        public boolean onMenuItemClick(MenuItem item) {
                            TabUtils.openUrlInNewTab(false, topSite.getDestinationUrl());
                            return true;
                        }
                    });
                    menu.add(R.string.contextmenu_open_in_incognito_tab).setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
                        @Override
                        public boolean onMenuItemClick(MenuItem item) {
                            TabUtils.openUrlInNewTab(true, topSite.getDestinationUrl());
                            return true;
                        }
                    });
                    menu.add(R.string.contextmenu_save_link).setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
                        @Override
                        public boolean onMenuItemClick(MenuItem item) {
                            if (getTab() != null) {
                                OfflinePageBridge.getForProfile(mProfile).scheduleDownload(getTab().getWebContents(),
                                        OfflinePageBridge.NTP_SUGGESTIONS_NAMESPACE, topSite.getDestinationUrl(), DownloadUiActionFlags.ALL);
                            } else {
                                RequestCoordinatorBridge.getForProfile(mProfile).savePageLater(
                                    topSite.getDestinationUrl(), OfflinePageBridge.NTP_SUGGESTIONS_NAMESPACE, true /* userRequested */);
                            }
                            return true;
                        }
                    });
                    menu.add(R.string.remove).setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
                        @Override
                        public boolean onMenuItemClick(MenuItem item) {
                            NTPUtil.imageCache.remove(topSite.getDestinationUrl());
                            mDatabaseHelper.deleteTopSite(topSite.getDestinationUrl());
                            NTPUtil.addToRemovedTopSite(topSite.getDestinationUrl());
                            superReferralSitesLayout.removeView(view);
                            return true;
                        }
                    });
                }
            });
            superReferralSitesLayout.addView(view);
        }
        showWidgets();
    }

    public void setTab(Tab tab) {
        mTab = tab;
    }

    private Tab getTab() {
        assert mTab != null;
        return mTab;
    }

    private TabImpl getTabImpl() {
        return (TabImpl) getTab();
    }

    private void updateAndShowIndicators(int position) {
        indicatorLayout.removeAllViews();
        for (int i = 0; i < ntpWidgetAdapter.getCount(); i++) {
            TextView dotTextView = new TextView(mActivity);
            dotTextView.setText(Html.fromHtml("&#9679;"));
            dotTextView.setTextColor(getResources().getColor(android.R.color.white));
            dotTextView.setTextSize(8);
            if (position == i) {
                dotTextView.setAlpha(1.0f);
            } else {
                dotTextView.setAlpha(0.4f);
            }
            indicatorLayout.addView(dotTextView);
        }
    }

    // NTP related methods
    private NTPWidgetAdapter.NTPWidgetListener ntpWidgetListener =
            new NTPWidgetAdapter.NTPWidgetListener() {
                @Override
                public void onMenuEdit() {
                    cancelTimer();
                    openWidgetStack();
                }

                @Override
                public void onMenuRemove(int position, boolean isBinanceWidget) {
                    if (isBinanceWidget) {
                        mBinanceNativeWorker.revokeToken();
                        BinanceWidgetManager.getInstance().setBinanceAccountBalance("");
                        BinanceWidgetManager.getInstance().setUserAuthenticationForBinance(false);
                        if (cryptoWidgetBottomSheetDialogFragment != null) {
                            cryptoWidgetBottomSheetDialogFragment.dismiss();
                        }
                    }

                    if (BraveActivity.getBraveActivity() != null 
                        && BraveActivity.getBraveActivity().getActivityTab() != null 
                        && !UserPrefs.get(Profile.getLastUsedRegularProfile())
                            .getBoolean(BravePref.NEW_TAB_PAGE_SHOW_BACKGROUND_IMAGE)
                        && NTPWidgetManager.getInstance().getUsedWidgets().size() <= 0) {
                        BraveActivity.getBraveActivity().getActivityTab().reloadIgnoringCache();
                    } else {
                        showWidgets();
                    }
                }

                @Override
                public void onMenuLearnMore() {
                    TabUtils.openUrlInSameTab(BRAVE_BINANCE);
                }

                @Override
                public void onMenuRefreshData() {
                    mBinanceNativeWorker.getAccountBalances();
                }

                @Override
                public void onMenuDisconnect() {
                    mBinanceNativeWorker.revokeToken();
                    BinanceWidgetManager.getInstance().setBinanceAccountBalance("");
                    BinanceWidgetManager.getInstance().setUserAuthenticationForBinance(false);
                    if (cryptoWidgetBottomSheetDialogFragment != null) {
                        cryptoWidgetBottomSheetDialogFragment.dismiss();
                    }
                    // Reset binance widget to connect page
                    showWidgets();
                }
            };

    private BinanceObserver mBinanaceObserver = new BinanceObserver() {
        @Override
        public void OnGetAccessToken(boolean isSuccess) {
            BinanceWidgetManager.getInstance().setUserAuthenticationForBinance(isSuccess);
            if (isSuccess) {
                mBinanceNativeWorker.getAccountBalances();
                if (bianceDisconnectLayout != null) {
                    bianceDisconnectLayout.setVisibility(View.GONE);
                }
                if (binanceWidgetProgress != null) {
                    binanceWidgetProgress.setVisibility(View.VISIBLE);
                }
            }
        };

        @Override
        public void OnGetAccountBalances(String jsonBalances, boolean isSuccess) {
            if (InternetConnection.isNetworkAvailable(mActivity)) {
                if (!isSuccess) {
                    BinanceWidgetManager.getInstance().setUserAuthenticationForBinance(isSuccess);
                    if (cryptoWidgetBottomSheetDialogFragment != null) {
                        cryptoWidgetBottomSheetDialogFragment.dismiss();
                    }
                } else {
                    if (jsonBalances != null && !TextUtils.isEmpty(jsonBalances)) {
                        BinanceWidgetManager.getInstance().setBinanceAccountBalance(jsonBalances);
                    }
                    try {
                        BinanceWidgetManager.binanceAccountBalance = new BinanceAccountBalance(
                                BinanceWidgetManager.getInstance().getBinanceAccountBalance());
                    } catch (JSONException e) {
                        Log.e("NTP", e.getMessage());
                    }
                }
            }
            // Reset binance widget to connect page
            showWidgets();
        };
    };

    // start timer function
    public void startTimer() {
        if (countDownTimer == null) {
            countDownTimer = new Timer();
            final Handler handler = new Handler();
            countDownTimer.scheduleAtFixedRate(new TimerTask() {
                @Override
                public void run() {
                    handler.post(new Runnable() {
                        @Override
                        public void run() {
                            if (BinanceWidgetManager.getInstance()
                                            .isUserAuthenticatedForBinance()) {
                                mBinanceNativeWorker.getAccountBalances();
                            }
                        }
                    });
                }
            }, 0, 30000);
        }
    }

    // cancel timer
    public void cancelTimer() {
        if (countDownTimer != null) {
            countDownTimer.cancel();
            countDownTimer.purge();
            countDownTimer = null;
        }
    }

    public void openWidgetStack() {
        final FragmentManager fm = ((BraveActivity) mActivity).getSupportFragmentManager();
        Fragment auxiliary = new Fragment() {
            @Override
            public void onActivityResult(int requestCode, int resultCode, Intent data) {
                super.onActivityResult(requestCode, resultCode, data);
                fm.beginTransaction().remove(this).commit();
                if (requestCode == NTP_WIDGET_STACK_CODE) {
                    showWidgets();
                }
            }
        };
        fm.beginTransaction().add(auxiliary, "FRAGMENT_TAG").commit();
        fm.executePendingTransactions();

        Intent ntpWidgetStackActivityIntent = new Intent(mActivity, NTPWidgetStackActivity.class);
        ntpWidgetStackActivityIntent.putExtra(NTPWidgetStackActivity.FROM_SETTINGS, false);
        auxiliary.startActivityForResult(ntpWidgetStackActivityIntent, NTP_WIDGET_STACK_CODE);
    }

    @Override
    public void onTileCountChanged() {
        if (mTopsiteErrorMessage == null) {
            return;
        }

        boolean showPlaceholder =
                mTileGroup != null && mTileGroup.hasReceivedData() && mTileGroup.isEmpty();
        if (!showPlaceholder) {
            mTopsiteErrorMessage.setVisibility(View.GONE);
        } else {
            mTopsiteErrorMessage.setVisibility(View.VISIBLE);
        }
    }

    @Override
    public void onCryptoWidgetBottomSheetDialogDismiss() {
        startTimer();
    }

    @Override
    public void onCloseClick(View view) {
        Log.d("bn", "close click");
    }

    @Override
    public void onOptInClick(View view) {
        Log.d("bn", "optin click");
    }

    @Override
    public void onCardClick(View view, int position) {
        Log.d("bn","cardclicklistener position" + adapterFeedCard.getItem(position) + " on row number " + position);
        BraveActivity.getBraveActivity().setNewsFeedScrollPosition(position);
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

    interface RepositoryCallback<T> {
        void onComplete(NewsFeedResponse<T> result);
    }

}
