#import "YTLite.h"

@interface YTSettingsSectionItemManager (YTLite)
- (void)updateYTLiteSectionWithEntry:(id)entry;
@end

static const NSInteger YTLiteSection = 789;

static NSString *GetCacheSize() {
    NSString *cachePath = NSSearchPathForDirectoriesInDomains(NSCachesDirectory, NSUserDomainMask, YES).firstObject;
    NSArray *filesArray = [[NSFileManager defaultManager] subpathsOfDirectoryAtPath:cachePath error:nil];

    unsigned long long int folderSize = 0;
    for (NSString *fileName in filesArray) {
        NSString *filePath = [cachePath stringByAppendingPathComponent:fileName];
        NSDictionary *fileAttributes = [[NSFileManager defaultManager] attributesOfItemAtPath:filePath error:nil];
        folderSize += [fileAttributes fileSize];
    }

    NSByteCountFormatter *formatter = [[NSByteCountFormatter alloc] init];
    formatter.countStyle = NSByteCountFormatterCountStyleFile;
    return [formatter stringFromByteCount:folderSize];
}

// Settings
%hook YTAppSettingsPresentationData
+ (NSArray *)settingsCategoryOrder {
    NSArray *order = %orig;
    NSMutableArray *mutableOrder = [order mutableCopy];
    NSUInteger insertIndex = [order indexOfObject:@(1)];
    if (insertIndex != NSNotFound)
        [mutableOrder insertObject:@(YTLiteSection) atIndex:insertIndex + 1];
    return mutableOrder;
}
%end

%hook YTSettingsSectionController
- (void)setSelectedItem:(NSUInteger)selectedItem {
    if (selectedItem != NSNotFound) %orig;
}
%end

%hook YTSettingsCell
- (void)layoutSubviews {
    %orig;

    BOOL isYTLite = [self.accessibilityIdentifier isEqualToString:@"YTLiteSectionItem"];
    YTTouchFeedbackController *feedback = [self valueForKey:@"_touchFeedbackController"];
    ABCSwitch *abcSwitch = [self valueForKey:@"_switch"];

    if (isYTLite) {
        feedback.feedbackColor = [UIColor colorWithRed:0.75 green:0.50 blue:0.90 alpha:1.0];
        abcSwitch.onTintColor = [UIColor colorWithRed:0.75 green:0.50 blue:0.90 alpha:1.0];
    }
}
%end

%hook YTSettingsSectionItemManager
%new
- (YTSettingsSectionItem *)switchWithTitle:(NSString *)title key:(NSString *)key {
    Class YTSettingsSectionItemClass = %c(YTSettingsSectionItem);
    Class YTAlertViewClass = %c(YTAlertView);
    NSString *titleDesc = [NSString stringWithFormat:@"%@Desc", title];

    YTSettingsSectionItem *item = [YTSettingsSectionItemClass switchItemWithTitle:LOC(title)
    titleDescription:LOC(titleDesc)
    accessibilityIdentifier:@"YTLiteSectionItem"
    switchOn:ytlBool(key)
    switchBlock:^BOOL(YTSettingsCell *cell, BOOL enabled) {
        if ([key isEqualToString:@"shortsOnlyMode"]) {
            YTAlertView *alertView = [YTAlertViewClass confirmationDialogWithAction:^{
                ytlSetBool(enabled, @"shortsOnlyMode");
            }
            actionTitle:LOC(@"Yes")
            cancelAction:^{
                [cell setSwitchOn:!enabled animated:YES];
            }
            cancelTitle:LOC(@"No")];
            alertView.title = LOC(@"Warning");
            alertView.subtitle = LOC(@"ShortsOnlyWarning");
            [alertView show];
        } else {
            ytlSetBool(enabled, key);

            NSArray *keys = @[@"removeLabels", @"removeIndicators", @"reExplore", @"addExplore", @"removeShorts", @"removeSubscriptions", @"removeUploads", @"removeLibrary", @"hideHypeTab"];
            if ([keys containsObject:key]) {
                [[[%c(YTHeaderContentComboViewController) alloc] init] refreshPivotBar];
            }
        }
        return YES;
    }
    settingItemId:0];

    return item;
}

%new
- (YTSettingsSectionItem *)linkWithTitle:(NSString *)title description:(NSString *)description link:(NSString *)link {
    return [%c(YTSettingsSectionItem) itemWithTitle:title
    titleDescription:description
    accessibilityIdentifier:@"YTLiteSectionItem"
    detailTextBlock:nil
    selectBlock:^BOOL (YTSettingsCell *cell, NSUInteger arg1) {
        return [%c(YTUIUtils) openURL:[NSURL URLWithString:link]];
    }];
}

%new(v@:@)
- (void)updateYTLiteSectionWithEntry:(id)entry {
    NSMutableArray *sectionItems = [NSMutableArray array];
    Class YTSettingsSectionItemClass = %c(YTSettingsSectionItem);
    YTSettingsViewController *settingsViewController = [self valueForKey:@"_settingsViewControllerDelegate"];

    YTSettingsSectionItem *space = [%c(YTSettingsSectionItem) itemWithTitle:nil accessibilityIdentifier:@"YTLiteSectionItem" detailTextBlock:nil selectBlock:nil];

    // ── General ──────────────────────────────────────────────────────────────
    YTSettingsSectionItem *general = [YTSettingsSectionItemClass itemWithTitle:LOC(@"General")
        accessibilityIdentifier:@"YTLiteSectionItem"
        detailTextBlock:^NSString *() { return @"‣"; }
        selectBlock:^BOOL (YTSettingsCell *cell, NSUInteger arg1) {
            NSArray <YTSettingsSectionItem *> *rows = @[
                [self switchWithTitle:@"RemoveAds" key:@"noAds"],
                [self switchWithTitle:@"BackgroundPlayback" key:@"backgroundPlayback"]
            ];
            YTSettingsPickerViewController *picker = [[%c(YTSettingsPickerViewController) alloc] initWithNavTitle:LOC(@"General") pickerSectionTitle:nil rows:rows selectedItemIndex:NSNotFound parentResponder:[self parentResponder]];
            [settingsViewController pushViewController:picker];
            return YES;
        }];
    [sectionItems addObject:general];

    // ── Navbar ────────────────────────────────────────────────────────────────
    YTSettingsSectionItem *navbar = [YTSettingsSectionItemClass itemWithTitle:LOC(@"Navbar")
        accessibilityIdentifier:@"YTLiteSectionItem"
        detailTextBlock:^NSString *() { return @"‣"; }
        selectBlock:^BOOL (YTSettingsCell *cell, NSUInteger arg1) {
            NSArray <YTSettingsSectionItem *> *rows = @[
                [self switchWithTitle:@"RemoveCast" key:@"noCast"],
                [self switchWithTitle:@"RemoveNotifications" key:@"noNotifsButton"],
                [self switchWithTitle:@"RemoveSearch" key:@"noSearchButton"],
                [self switchWithTitle:@"RemoveVoiceSearch" key:@"noVoiceSearchButton"]
            ];
            if (ytlBool(@"advancedMode")) {
                rows = [rows arrayByAddingObjectsFromArray:@[
                    [self switchWithTitle:@"StickyNavbar" key:@"stickyNavbar"],
                    [self switchWithTitle:@"NoSubbar" key:@"noSubbar"],
                    [self switchWithTitle:@"NoYTLogo" key:@"noYTLogo"],
                    [self switchWithTitle:@"PremiumYTLogo" key:@"premiumYTLogo"]
                ]];
            }
            YTSettingsPickerViewController *picker = [[%c(YTSettingsPickerViewController) alloc] initWithNavTitle:LOC(@"Navbar") pickerSectionTitle:nil rows:rows selectedItemIndex:NSNotFound parentResponder:[self parentResponder]];
            [settingsViewController pushViewController:picker];
            return YES;
        }];
    [sectionItems addObject:navbar];

    // ── Feed ─────────────────────────────────────────────────────────────────
    YTSettingsSectionItem *feed = [YTSettingsSectionItemClass itemWithTitle:LOC(@"Feed")
        accessibilityIdentifier:@"YTLiteSectionItem"
        detailTextBlock:^NSString *() { return @"‣"; }
        selectBlock:^BOOL (YTSettingsCell *cell, NSUInteger arg1) {
            NSArray <YTSettingsSectionItem *> *rows = @[
                [self switchWithTitle:@"HideShorts" key:@"hideShorts"],
                [self switchWithTitle:@"KeepSubsShorts" key:@"keepSubsShorts"],
                [self switchWithTitle:@"RemoveCommunityPosts" key:@"removeCommunityPosts"],
                [self switchWithTitle:@"RemoveMixPlaylists" key:@"removeMixPlaylists"],
                [self switchWithTitle:@"RemoveLiveVids" key:@"removeLiveVids"],
                [self switchWithTitle:@"RemoveHorizontalFeeds" key:@"removeHorizontalFeeds"],
                [self switchWithTitle:@"RemoveMoreTopics" key:@"removeMoreTopics"],
                [self switchWithTitle:@"RemovePlayables" key:@"removePlayables"],
                [self switchWithTitle:@"FixAlbums" key:@"fixAlbums"]
            ];
            YTSettingsPickerViewController *picker = [[%c(YTSettingsPickerViewController) alloc] initWithNavTitle:LOC(@"Feed") pickerSectionTitle:nil rows:rows selectedItemIndex:NSNotFound parentResponder:[self parentResponder]];
            [settingsViewController pushViewController:picker];
            return YES;
        }];
    [sectionItems addObject:feed];

    if (ytlBool(@"advancedMode")) {
        // ── Overlay ───────────────────────────────────────────────────────────
        YTSettingsSectionItem *overlay = [YTSettingsSectionItemClass itemWithTitle:LOC(@"Overlay")
            accessibilityIdentifier:@"YTLiteSectionItem"
            detailTextBlock:^NSString *() { return @"‣"; }
            selectBlock:^BOOL (YTSettingsCell *cell, NSUInteger arg1) {
                NSArray <YTSettingsSectionItem *> *rows = @[
                    [self switchWithTitle:@"HideAutoplay" key:@"hideAutoplay"],
                    [self switchWithTitle:@"HideSubs" key:@"hideSubs"],
                    [self switchWithTitle:@"NoHudMsgs" key:@"noHUDMsgs"],
                    [self switchWithTitle:@"HidePrevNext" key:@"hidePrevNext"],
                    [self switchWithTitle:@"ReplacePrevNext" key:@"replacePrevNext"],
                    [self switchWithTitle:@"NoDarkBg" key:@"noDarkBg"],
                    [self switchWithTitle:@"NoEndScreenCards" key:@"endScreenCards"],
                    [self switchWithTitle:@"NoAutonavEndScreenCards" key:@"noAutonavEndScreenCards"],
                    [self switchWithTitle:@"NoFullscreenActions" key:@"noFullscreenActions"],
                    [self switchWithTitle:@"PersistentProgressBar" key:@"persistentProgressBar"],
                    [self switchWithTitle:@"StockVolumeHUD" key:@"stockVolumeHUD"],
                    [self switchWithTitle:@"DisableAmbientMode" key:@"disableAmbientMode"],
                    [self switchWithTitle:@"NoRelatedVids" key:@"noRelatedVids"],
                    [self switchWithTitle:@"NoPromotionCards" key:@"noPromotionCards"],
                    [self switchWithTitle:@"NoWatermarks" key:@"noWatermarks"],
                    [self switchWithTitle:@"VideoEndTime" key:@"videoEndTime"],
                    [self switchWithTitle:@"24hrFormat" key:@"24hrFormat"]
                ];
                YTSettingsPickerViewController *picker = [[%c(YTSettingsPickerViewController) alloc] initWithNavTitle:LOC(@"Overlay") pickerSectionTitle:nil rows:rows selectedItemIndex:NSNotFound parentResponder:[self parentResponder]];
                [settingsViewController pushViewController:picker];
                return YES;
            }];
        [sectionItems addObject:overlay];

        // ── Player ────────────────────────────────────────────────────────────
        YTSettingsSectionItem *player = [YTSettingsSectionItemClass itemWithTitle:LOC(@"Player")
            accessibilityIdentifier:@"YTLiteSectionItem"
            detailTextBlock:^NSString *() { return @"‣"; }
            selectBlock:^BOOL (YTSettingsCell *cell, NSUInteger arg1) {
                NSArray <YTSettingsSectionItem *> *rows = @[
                    [self switchWithTitle:@"Miniplayer" key:@"miniplayer"],
                    [self switchWithTitle:@"PortraitFullscreen" key:@"portraitFullscreen"],
                    [self switchWithTitle:@"CopyWithTimestamp" key:@"copyWithTimestamp"],
                    [self switchWithTitle:@"DisableAutoplay" key:@"disableAutoplay"],
                    [self switchWithTitle:@"DisableAutoCaptions" key:@"disableAutoCaptions"],
                    [self switchWithTitle:@"NoContentWarning" key:@"noContentWarning"],
                    [self switchWithTitle:@"ClassicQuality" key:@"classicQuality"],
                    [self switchWithTitle:@"ExtraSpeedOptions" key:@"extraSpeedOptions"],
                    [self switchWithTitle:@"RememberLoopMode" key:@"rememberLoopMode"],
                    [self switchWithTitle:@"DontSnap2Chapter" key:@"dontSnapToChapter"],
                    [self switchWithTitle:@"NoTwoFingerSnapToChapter" key:@"noTwoFingerSnapToChapter"],
                    [self switchWithTitle:@"PauseOnOverlay" key:@"pauseOnOverlay"],
                    [self switchWithTitle:@"RedProgressBar" key:@"redProgressBar"],
                    [self switchWithTitle:@"NoPlayerRemixButton" key:@"noPlayerRemixButton"],
                    [self switchWithTitle:@"NoPlayerClipButton" key:@"noPlayerClipButton"],
                    [self switchWithTitle:@"NoPlayerDownloadButton" key:@"noPlayerDownloadButton"],
                    [self switchWithTitle:@"NoHints" key:@"noHints"],
                    [self switchWithTitle:@"NoFreeZoom" key:@"noFreeZoom"],
                    [self switchWithTitle:@"AutoFullscreen" key:@"autoFullscreen"],
                    [self switchWithTitle:@"ExitFullscreen" key:@"exitFullscreen"],
                    [self switchWithTitle:@"NoDoubleTap2Seek" key:@"noDoubleTapToSeek"]
                ];
                YTSettingsPickerViewController *picker = [[%c(YTSettingsPickerViewController) alloc] initWithNavTitle:LOC(@"Player") pickerSectionTitle:nil rows:rows selectedItemIndex:NSNotFound parentResponder:[self parentResponder]];
                [settingsViewController pushViewController:picker];
                return YES;
            }];
        [sectionItems addObject:player];

        // ── Shorts ────────────────────────────────────────────────────────────
        YTSettingsSectionItem *shorts = [YTSettingsSectionItemClass itemWithTitle:LOC(@"Shorts")
            accessibilityIdentifier:@"YTLiteSectionItem"
            detailTextBlock:^NSString *() { return @"‣"; }
            selectBlock:^BOOL (YTSettingsCell *cell, NSUInteger arg1) {
                NSArray <YTSettingsSectionItem *> *rows = @[
                    [self switchWithTitle:@"ShortsOnlyMode" key:@"shortsOnlyMode"],
                    [self switchWithTitle:@"AutoSkipShorts" key:@"autoSkipShorts"],
                    [self switchWithTitle:@"HideShorts" key:@"hideShorts"],
                    [self switchWithTitle:@"ShortsProgress" key:@"shortsProgress"],
                    [self switchWithTitle:@"PinchToFullscreenShorts" key:@"pinchToFullscreenShorts"],
                    [self switchWithTitle:@"ShortsToRegular" key:@"shortsToRegular"],
                    [self switchWithTitle:@"ResumeShorts" key:@"resumeShorts"],
                    [self switchWithTitle:@"HideShortsLogo" key:@"hideShortsLogo"],
                    [self switchWithTitle:@"HideShortsSearch" key:@"hideShortsSearch"],
                    [self switchWithTitle:@"HideShortsCamera" key:@"hideShortsCamera"],
                    [self switchWithTitle:@"HideShortsMore" key:@"hideShortsMore"],
                    [self switchWithTitle:@"HideShortsSubscriptions" key:@"hideShortsSubscriptions"],
                    [self switchWithTitle:@"HideShortsSubscribe" key:@"hideShortsSubscribe"],
                    [self switchWithTitle:@"HideShortsUsername" key:@"hideShortsUsername"],
                    [self switchWithTitle:@"HideShortsLike" key:@"hideShortsLike"],
                    [self switchWithTitle:@"HideShortsDislike" key:@"hideShortsDislike"],
                    [self switchWithTitle:@"HideShortsComments" key:@"hideShortsComments"],
                    [self switchWithTitle:@"HideShortsRemix" key:@"hideShortsRemix"],
                    [self switchWithTitle:@"HideShortsShare" key:@"hideShortsShare"],
                    [self switchWithTitle:@"HideShortsAudioButton" key:@"hideShortsAudioButton"],
                    [self switchWithTitle:@"HideShortsSuggestion" key:@"hideShortsSuggestion"],
                    [self switchWithTitle:@"HideShortsAvatars" key:@"hideShortsAvatars"],
                    [self switchWithTitle:@"HideShortsThanks" key:@"hideShortsThanks"],
                    [self switchWithTitle:@"HideShortsProducts" key:@"hideShortsProducts"],
                    [self switchWithTitle:@"HideShortsSource" key:@"hideShortsSource"],
                    [self switchWithTitle:@"HideShortsChannelName" key:@"hideShortsChannelName"],
                    [self switchWithTitle:@"HideShortsDescription" key:@"hideShortsDescription"],
                    [self switchWithTitle:@"HideShortsAudio" key:@"hideShortsAudioTrack"],
                    [self switchWithTitle:@"NoPromotionCards" key:@"hideShortsPromoCards"]
                ];
                YTSettingsPickerViewController *picker = [[%c(YTSettingsPickerViewController) alloc] initWithNavTitle:LOC(@"Shorts") pickerSectionTitle:nil rows:rows selectedItemIndex:NSNotFound parentResponder:[self parentResponder]];
                [settingsViewController pushViewController:picker];
                return YES;
            }];
        [sectionItems addObject:shorts];
    }

    // ── Tabbar ────────────────────────────────────────────────────────────
    YTSettingsSectionItem *tabbar = [YTSettingsSectionItemClass itemWithTitle:LOC(@"Tabbar")
        accessibilityIdentifier:@"YTLiteSectionItem"
        detailTextBlock:^NSString *() { return @"‣"; }
        selectBlock:^BOOL (YTSettingsCell *cell, NSUInteger arg1) {
            NSArray <YTSettingsSectionItem *> *rows = @[
                [self switchWithTitle:@"TranslucentBar" key:@"translucentBar"],
                [self switchWithTitle:@"RemoveLabels" key:@"removeLabels"],
                [self switchWithTitle:@"RemoveIndicators" key:@"removeIndicators"],
                [self switchWithTitle:@"RemoveShortsTab" key:@"removeShorts"],
                [self switchWithTitle:@"RemoveSubscriptionsTab" key:@"removeSubscriptions"],
                [self switchWithTitle:@"RemoveUploadsTab" key:@"removeUploads"],
                [self switchWithTitle:@"RemoveLibraryTab" key:@"removeLibrary"],
                [self switchWithTitle:@"HideHypeTab" key:@"hideHypeTab"]
            ];
            YTSettingsPickerViewController *picker = [[%c(YTSettingsPickerViewController) alloc] initWithNavTitle:LOC(@"Tabbar") pickerSectionTitle:nil rows:rows selectedItemIndex:NSNotFound parentResponder:[self parentResponder]];
            [settingsViewController pushViewController:picker];
            return YES;
        }];
    [sectionItems addObject:tabbar];

    // ── Other ─────────────────────────────────────────────────────────────
    YTSettingsSectionItem *other = [YTSettingsSectionItemClass itemWithTitle:LOC(@"Other")
        accessibilityIdentifier:@"YTLiteSectionItem"
        detailTextBlock:^NSString *() { return @"‣"; }
        selectBlock:^BOOL (YTSettingsCell *cell, NSUInteger arg1) {
            YTSettingsSectionItem *contextMenu = [YTSettingsSectionItemClass itemWithTitle:LOC(@"ContextMenu")
                accessibilityIdentifier:@"YTLiteSectionItem"
                detailTextBlock:^NSString *() { return @"‣"; }
                selectBlock:^BOOL (YTSettingsCell *cell2, NSUInteger arg2) {
                    NSArray <YTSettingsSectionItem *> *menuRows = @[
                        [self switchWithTitle:@"RemovePlayNext" key:@"removePlayNext"],
                        [self switchWithTitle:@"RemoveDownloadMenu" key:@"removeDownloadMenu"],
                        [self switchWithTitle:@"RemoveWatchLaterMenu" key:@"removeWatchLaterMenu"],
                        [self switchWithTitle:@"RemoveSaveToPlaylistMenu" key:@"removeSaveToPlaylistMenu"],
                        [self switchWithTitle:@"RemoveShareMenu" key:@"removeShareMenu"],
                        [self switchWithTitle:@"RemoveNotInterestedMenu" key:@"removeNotInterestedMenu"],
                        [self switchWithTitle:@"RemoveDontRecommendMenu" key:@"removeDontRecommendMenu"],
                        [self switchWithTitle:@"RemoveFeedbackMenu" key:@"removeFeedbackMenu"],
                        [self switchWithTitle:@"RemoveReportMenu" key:@"removeReportMenu"],
                        [self switchWithTitle:@"RemoveRemixMenu" key:@"removeRemixMenu"],
                        [self switchWithTitle:@"RemoveYTMMenu" key:@"removeYTMMenu"],
                        [self switchWithTitle:@"RemoveCommentGuidelines" key:@"removeCommentGuidelines"]
                    ];
                    YTSettingsPickerViewController *menuPicker = [[%c(YTSettingsPickerViewController) alloc] initWithNavTitle:LOC(@"ContextMenu") pickerSectionTitle:nil rows:menuRows selectedItemIndex:NSNotFound parentResponder:[self parentResponder]];
                    [settingsViewController pushViewController:menuPicker];
                    return YES;
                }];

            NSArray <YTSettingsSectionItem *> *rows = @[
                [self switchWithTitle:@"NoLinkTracking" key:@"noLinkTracking"],
                [self switchWithTitle:@"NoShareChunk" key:@"noShareChunk"],
                [self switchWithTitle:@"NativeShare" key:@"nativeShare"],
                [self switchWithTitle:@"AutoCheckLinks" key:@"autoCheckLinks"],
                contextMenu,
                [self switchWithTitle:@"NoDonationReminder" key:@"noDonationReminder"],
                [self switchWithTitle:@"ClearCacheAtStart" key:@"clearCacheAtStart"]
            ];
            YTSettingsPickerViewController *picker = [[%c(YTSettingsPickerViewController) alloc] initWithNavTitle:LOC(@"Other") pickerSectionTitle:nil rows:rows selectedItemIndex:NSNotFound parentResponder:[self parentResponder]];
            [settingsViewController pushViewController:picker];
            return YES;
        }];
    [sectionItems addObject:other];

    // ── AdvancedMode (always visible) ─────────────────────────────────────
    [sectionItems addObject:[self switchWithTitle:@"AdvancedMode" key:@"advancedMode"]];

    [sectionItems addObject:space];

    // ── Cache management ──────────────────────────────────────────────────
    YTSettingsSectionItem *clearCache = [YTSettingsSectionItemClass itemWithTitle:LOC(@"ClearCache")
        accessibilityIdentifier:@"YTLiteSectionItem"
        detailTextBlock:^NSString *() { return GetCacheSize(); }
        selectBlock:^BOOL (YTSettingsCell *cacheCell, NSUInteger arg1) {
            NSString *cachePath = NSSearchPathForDirectoriesInDomains(NSCachesDirectory, NSUserDomainMask, YES).firstObject;
            [[NSFileManager defaultManager] removeItemAtPath:cachePath error:nil];
            [[NSFileManager defaultManager] createDirectoryAtPath:cachePath withIntermediateDirectories:YES attributes:nil error:nil];
            [cacheCell setDetailText:GetCacheSize()];
            return YES;
        }];
    [sectionItems addObject:clearCache];

    [sectionItems addObject:space];

    // ── Developer links ───────────────────────────────────────────────────
    [sectionItems addObject:[self linkWithTitle:LOC(@"VisitGithub") description:LOC(@"VisitGithubDesc") link:@"https://github.com/the-big-mini/ytlite"]];

    [sectionItems addObject:space];

    // ── Version ───────────────────────────────────────────────────────────
    YTSettingsSectionItem *versionItem = [YTSettingsSectionItemClass itemWithTitle:@"YTLite"
        accessibilityIdentifier:@"YTLiteSectionItem"
        detailTextBlock:^NSString *() {
            return [NSString stringWithFormat:@"v%s", TWEAK_VERSION];
        }
        selectBlock:nil];
    [sectionItems addObject:versionItem];

    [settingsViewController setSectionItems:sectionItems forCategory:YTLiteSection title:@"YTLite" titleDescription:nil headerHidden:YES];
}

- (void)updateSectionForCategory:(NSUInteger)category withEntry:(id)entry {
    if (category == YTLiteSection) {
        [self updateYTLiteSectionWithEntry:entry];
        return;
    }
    %orig;
}
%end
