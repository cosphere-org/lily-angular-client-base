/**
 * Facade Service for all domains
 */
import { Injectable, Injector } from '@angular/core';
import { Observable } from 'rxjs';

import { DataState, Options } from './client.interface';

import * as X from '../domains/index';

@Injectable()
export class APIService {

    constructor(private injector: Injector) {}

    /**
     * Account Settings Management domain
     */
    private _account_settingsDomain: X.AccountSettingsDomain;
    
    public get account_settingsDomain(): X.AccountSettingsDomain {
        if (!this._account_settingsDomain) {
            this._account_settingsDomain = this.injector.get(X.AccountSettingsDomain);
        }
    
        return this._account_settingsDomain;
    }

    readAccountsetting(): DataState<X.ReadAccountsettingResponse> {
        return this.account_settingsDomain.readAccountsetting();
    }

    updateAccountsetting(body: X.UpdateAccountsettingBody): Observable<X.UpdateAccountsettingResponse> {
        return this.account_settingsDomain.updateAccountsetting(body);
    }

    /**
     * Accounts Management domain
     */
    private _accountsDomain: X.AccountsDomain;
    
    public get accountsDomain(): X.AccountsDomain {
        if (!this._accountsDomain) {
            this._accountsDomain = this.injector.get(X.AccountsDomain);
        }
    
        return this._accountsDomain;
    }

    activateAccount(body: X.ActivateAccountBody): Observable<X.ActivateAccountResponse> {
        return this.accountsDomain.activateAccount(body);
    }

    authenticateUser(body: X.AuthenticateUserBody): Observable<X.AuthenticateUserResponse> {
        return this.accountsDomain.authenticateUser(body);
    }

    bulkReadAccounts(params: X.BulkReadAccountsQuery): DataState<X.BulkReadAccountsResponse> {
        return this.accountsDomain.bulkReadAccounts(params);
    }

    changePassword(body: X.ChangePasswordBody): Observable<X.ChangePasswordResponse> {
        return this.accountsDomain.changePassword(body);
    }

    createAccount(body: X.CreateAccountBody): Observable<X.CreateAccountResponse> {
        return this.accountsDomain.createAccount(body);
    }

    readAccount(): DataState<X.ReadAccountResponse> {
        return this.accountsDomain.readAccount();
    }

    resetPassword(body: X.ResetPasswordBody): Observable<X.ResetPasswordResponse> {
        return this.accountsDomain.resetPassword(body);
    }

    sendAccountActivationEmail(body: X.SendAccountActivationEmailBody): Observable<X.SendAccountActivationEmailResponse> {
        return this.accountsDomain.sendAccountActivationEmail(body);
    }

    sendResetPasswordEmail(body: X.SendResetPasswordEmailBody): Observable<X.SendResetPasswordEmailResponse> {
        return this.accountsDomain.sendResetPasswordEmail(body);
    }

    updateAccount(body: X.UpdateAccountBody): Observable<X.UpdateAccountResponse> {
        return this.accountsDomain.updateAccount(body);
    }

    /**
     * Attempt Stats Management domain
     */
    private _attempt_statsDomain: X.AttemptStatsDomain;
    
    public get attempt_statsDomain(): X.AttemptStatsDomain {
        if (!this._attempt_statsDomain) {
            this._attempt_statsDomain = this.injector.get(X.AttemptStatsDomain);
        }
    
        return this._attempt_statsDomain;
    }

    bulkReadAttemptstats(params: X.BulkReadAttemptstatsQuery): DataState<X.BulkReadAttemptstatsResponse> {
        return this.attempt_statsDomain.bulkReadAttemptstats(params);
    }

    createAttemptstat(body: X.CreateAttemptstatBody): Observable<X.CreateAttemptstatResponse> {
        return this.attempt_statsDomain.createAttemptstat(body);
    }

    createExternalAttemptStat(body: X.CreateExternalAttemptStatBody): Observable<X.CreateExternalAttemptStatResponse> {
        return this.attempt_statsDomain.createExternalAttemptStat(body);
    }

    /**
     * Attempts Management domain
     */
    private _attemptsDomain: X.AttemptsDomain;
    
    public get attemptsDomain(): X.AttemptsDomain {
        if (!this._attemptsDomain) {
            this._attemptsDomain = this.injector.get(X.AttemptsDomain);
        }
    
        return this._attemptsDomain;
    }

    bulkReadAttemptsByCards(cardId: any): DataState<X.BulkReadAttemptsByCardsResponse> {
        return this.attemptsDomain.bulkReadAttemptsByCards(cardId);
    }

    createAttempt(body: X.CreateAttemptBody): Observable<X.CreateAttemptResponse> {
        return this.attemptsDomain.createAttempt(body);
    }

    updateAttempt(attemptId: any, body: X.UpdateAttemptBody): Observable<X.UpdateAttemptResponse> {
        return this.attemptsDomain.updateAttempt(attemptId, body);
    }

    /**
     * Auth Tokens Management domain
     */
    private _auth_tokensDomain: X.AuthTokensDomain;
    
    public get auth_tokensDomain(): X.AuthTokensDomain {
        if (!this._auth_tokensDomain) {
            this._auth_tokensDomain = this.injector.get(X.AuthTokensDomain);
        }
    
        return this._auth_tokensDomain;
    }

    createAuthToken(body: X.CreateAuthTokenBody): Observable<X.CreateAuthTokenResponse> {
        return this.auth_tokensDomain.createAuthToken(body);
    }

    createFacebookBasedAuthToken(body: X.CreateFacebookBasedAuthTokenBody): Observable<X.CreateFacebookBasedAuthTokenResponse> {
        return this.auth_tokensDomain.createFacebookBasedAuthToken(body);
    }

    createFacebookBasedMobileAuthToken(body: X.CreateFacebookBasedMobileAuthTokenBody): Observable<X.CreateFacebookBasedMobileAuthTokenResponse> {
        return this.auth_tokensDomain.createFacebookBasedMobileAuthToken(body);
    }

    createGoogleBasedAuthToken(body: X.CreateGoogleBasedAuthTokenBody): Observable<X.CreateGoogleBasedAuthTokenResponse> {
        return this.auth_tokensDomain.createGoogleBasedAuthToken(body);
    }

    createGoogleBasedMobileAuthToken(body: X.CreateGoogleBasedMobileAuthTokenBody): Observable<X.CreateGoogleBasedMobileAuthTokenResponse> {
        return this.auth_tokensDomain.createGoogleBasedMobileAuthToken(body);
    }

    updateAuthToken(): Observable<X.UpdateAuthTokenResponse> {
        return this.auth_tokensDomain.updateAuthToken();
    }

    /**
     * Cards Management domain
     */
    private _cardsDomain: X.CardsDomain;
    
    public get cardsDomain(): X.CardsDomain {
        if (!this._cardsDomain) {
            this._cardsDomain = this.injector.get(X.CardsDomain);
        }
    
        return this._cardsDomain;
    }

    bulkDeleteCards(params: X.BulkDeleteCardsQuery): Observable<X.BulkDeleteCardsResponse> {
        return this.cardsDomain.bulkDeleteCards(params);
    }

    bulkReadCards(params: X.BulkReadCardsQuery): DataState<X.BulkReadCardsResponse> {
        return this.cardsDomain.bulkReadCards(params);
    }

    createCard(body: X.CreateCardBody): Observable<X.CreateCardResponse> {
        return this.cardsDomain.createCard(body);
    }

    readCard(cardId: any): DataState<X.ReadCardResponse> {
        return this.cardsDomain.readCard(cardId);
    }

    updateCard(cardId: any, body: X.UpdateCardBody): Observable<X.UpdateCardResponse> {
        return this.cardsDomain.updateCard(cardId, body);
    }

    /**
     * Categories Management domain
     */
    private _categoriesDomain: X.CategoriesDomain;
    
    public get categoriesDomain(): X.CategoriesDomain {
        if (!this._categoriesDomain) {
            this._categoriesDomain = this.injector.get(X.CategoriesDomain);
        }
    
        return this._categoriesDomain;
    }

    bulkReadCategories(): DataState<X.BulkReadCategoriesResponse> {
        return this.categoriesDomain.bulkReadCategories();
    }

    /**
     * Contact Management domain
     */
    private _contactsDomain: X.ContactsDomain;
    
    public get contactsDomain(): X.ContactsDomain {
        if (!this._contactsDomain) {
            this._contactsDomain = this.injector.get(X.ContactsDomain);
        }
    
        return this._contactsDomain;
    }

    createAnonymousContactAttempt(body: X.CreateAnonymousContactAttemptBody): Observable<X.CreateAnonymousContactAttemptResponse> {
        return this.contactsDomain.createAnonymousContactAttempt(body);
    }

    sendAuthenticatedContactMessage(body: X.SendAuthenticatedContactMessageBody): Observable<X.SendAuthenticatedContactMessageResponse> {
        return this.contactsDomain.sendAuthenticatedContactMessage(body);
    }

    verifyAnonymousContactAttempt(body: X.VerifyAnonymousContactAttemptBody): Observable<X.VerifyAnonymousContactAttemptResponse> {
        return this.contactsDomain.verifyAnonymousContactAttempt(body);
    }

    /**
     * Donations Management domain
     */
    private _donationsDomain: X.DonationsDomain;
    
    public get donationsDomain(): X.DonationsDomain {
        if (!this._donationsDomain) {
            this._donationsDomain = this.injector.get(X.DonationsDomain);
        }
    
        return this._donationsDomain;
    }

    checkIfCanAttemptDonation(params: X.CheckIfCanAttemptDonationQuery): DataState<X.CheckIfCanAttemptDonationResponse> {
        return this.donationsDomain.checkIfCanAttemptDonation(params);
    }

    createAnonymousDonation(body: X.CreateAnonymousDonationBody): Observable<X.CreateAnonymousDonationResponse> {
        return this.donationsDomain.createAnonymousDonation(body);
    }

    createDonation(body: X.CreateDonationBody): Observable<X.CreateDonationResponse> {
        return this.donationsDomain.createDonation(body);
    }

    createDonationattempt(body: X.CreateDonationattemptBody): Observable<X.CreateDonationattemptResponse> {
        return this.donationsDomain.createDonationattempt(body);
    }

    /**
     * External Apps Management domain
     */
    private _external_appsDomain: X.ExternalAppsDomain;
    
    public get external_appsDomain(): X.ExternalAppsDomain {
        if (!this._external_appsDomain) {
            this._external_appsDomain = this.injector.get(X.ExternalAppsDomain);
        }
    
        return this._external_appsDomain;
    }

    createExternalAppAuthToken(body: X.CreateExternalAppAuthTokenBody): Observable<X.CreateExternalAppAuthTokenResponse> {
        return this.external_appsDomain.createExternalAppAuthToken(body);
    }

    readExternalappconf(params: X.ReadExternalappconfQuery): DataState<X.ReadExternalappconfResponse> {
        return this.external_appsDomain.readExternalappconf(params);
    }

    /**
     * Focus Records Management domain
     */
    private _focus_recordsDomain: X.FocusRecordsDomain;
    
    public get focus_recordsDomain(): X.FocusRecordsDomain {
        if (!this._focus_recordsDomain) {
            this._focus_recordsDomain = this.injector.get(X.FocusRecordsDomain);
        }
    
        return this._focus_recordsDomain;
    }

    createFocusrecord(body: X.CreateFocusrecordBody): Observable<X.CreateFocusrecordResponse> {
        return this.focus_recordsDomain.createFocusrecord(body);
    }

    readFocusRecordSummary(): DataState<X.ReadFocusRecordSummaryResponse> {
        return this.focus_recordsDomain.readFocusRecordSummary();
    }

    /**
     * Fragment Hashtags Management domain
     */
    private _fragment_hashtagsDomain: X.FragmentHashtagsDomain;
    
    public get fragment_hashtagsDomain(): X.FragmentHashtagsDomain {
        if (!this._fragment_hashtagsDomain) {
            this._fragment_hashtagsDomain = this.injector.get(X.FragmentHashtagsDomain);
        }
    
        return this._fragment_hashtagsDomain;
    }

    bulkReadFragmentHashtags(params: X.BulkReadFragmentHashtagsQuery): DataState<X.BulkReadFragmentHashtagsResponse> {
        return this.fragment_hashtagsDomain.bulkReadFragmentHashtags(params);
    }

    bulkReadPublishedFragmentHashtags(params: X.BulkReadPublishedFragmentHashtagsQuery): DataState<X.BulkReadPublishedFragmentHashtagsResponse> {
        return this.fragment_hashtagsDomain.bulkReadPublishedFragmentHashtags(params);
    }

    /**
     * Fragment Words Management domain
     */
    private _fragment_wordsDomain: X.FragmentWordsDomain;
    
    public get fragment_wordsDomain(): X.FragmentWordsDomain {
        if (!this._fragment_wordsDomain) {
            this._fragment_wordsDomain = this.injector.get(X.FragmentWordsDomain);
        }
    
        return this._fragment_wordsDomain;
    }

    bulkReadFragmentWords(params: X.BulkReadFragmentWordsQuery): DataState<X.BulkReadFragmentWordsResponse> {
        return this.fragment_wordsDomain.bulkReadFragmentWords(params);
    }

    bulkReadPublishedFragmentWords(params: X.BulkReadPublishedFragmentWordsQuery): DataState<X.BulkReadPublishedFragmentWordsResponse> {
        return this.fragment_wordsDomain.bulkReadPublishedFragmentWords(params);
    }

    /**
     * Fragments Management domain
     */
    private _fragmentsDomain: X.FragmentsDomain;
    
    public get fragmentsDomain(): X.FragmentsDomain {
        if (!this._fragmentsDomain) {
            this._fragmentsDomain = this.injector.get(X.FragmentsDomain);
        }
    
        return this._fragmentsDomain;
    }

    bulkReadFragments(params: X.BulkReadFragmentsQuery): DataState<X.BulkReadFragmentsResponse> {
        return this.fragmentsDomain.bulkReadFragments(params);
    }

    bulkReadPublishedFragments(params: X.BulkReadPublishedFragmentsQuery): DataState<X.BulkReadPublishedFragmentsResponse> {
        return this.fragmentsDomain.bulkReadPublishedFragments(params);
    }

    createFragment(): Observable<X.CreateFragmentResponse> {
        return this.fragmentsDomain.createFragment();
    }

    deleteFragment(fragmentId: any): Observable<X.DeleteFragmentResponse> {
        return this.fragmentsDomain.deleteFragment(fragmentId);
    }

    mergeFragment(fragmentId: any): Observable<X.MergeFragmentResponse> {
        return this.fragmentsDomain.mergeFragment(fragmentId);
    }

    publishFragment(fragmentId: any): Observable<X.PublishFragmentResponse> {
        return this.fragmentsDomain.publishFragment(fragmentId);
    }

    readFragment(fragmentId: any): DataState<X.ReadFragmentResponse> {
        return this.fragmentsDomain.readFragment(fragmentId);
    }

    readFragmentDiff(fragmentId: any): DataState<X.ReadFragmentDiffResponse> {
        return this.fragmentsDomain.readFragmentDiff(fragmentId);
    }

    readFragmentSample(fragmentId: any): DataState<X.ReadFragmentSampleResponse> {
        return this.fragmentsDomain.readFragmentSample(fragmentId);
    }

    updateFragment(fragmentId: any, body: X.UpdateFragmentBody): Observable<X.UpdateFragmentResponse> {
        return this.fragmentsDomain.updateFragment(fragmentId, body);
    }

    /**
     * Geometries Management domain
     */
    private _geometriesDomain: X.GeometriesDomain;
    
    public get geometriesDomain(): X.GeometriesDomain {
        if (!this._geometriesDomain) {
            this._geometriesDomain = this.injector.get(X.GeometriesDomain);
        }
    
        return this._geometriesDomain;
    }

    bulkReadGeometries(params: X.BulkReadGeometriesQuery): DataState<X.BulkReadGeometriesResponse> {
        return this.geometriesDomain.bulkReadGeometries(params);
    }

    bulkUpdateGeometries(body: X.BulkUpdateGeometriesBody): Observable<X.BulkUpdateGeometriesResponse> {
        return this.geometriesDomain.bulkUpdateGeometries(body);
    }

    readGeometryByCard(cardId: any): DataState<X.ReadGeometryByCardResponse> {
        return this.geometriesDomain.readGeometryByCard(cardId);
    }

    readGraph(params: X.ReadGraphQuery): DataState<X.ReadGraphResponse> {
        return this.geometriesDomain.readGraph(params);
    }

    /**
     * Hashtags Management domain
     */
    private _hashtagsDomain: X.HashtagsDomain;
    
    public get hashtagsDomain(): X.HashtagsDomain {
        if (!this._hashtagsDomain) {
            this._hashtagsDomain = this.injector.get(X.HashtagsDomain);
        }
    
        return this._hashtagsDomain;
    }

    bulkReadHashtags(params: X.BulkReadHashtagsQuery): DataState<X.BulkReadHashtagsResponse> {
        return this.hashtagsDomain.bulkReadHashtags(params);
    }

    createHashtag(body: X.CreateHashtagBody): Observable<X.CreateHashtagResponse> {
        return this.hashtagsDomain.createHashtag(body);
    }

    deleteHashtag(hashtagId: any, params: X.DeleteHashtagQuery): Observable<X.DeleteHashtagResponse> {
        return this.hashtagsDomain.deleteHashtag(hashtagId, params);
    }

    readHashtagsToc(params: X.ReadHashtagsTocQuery): DataState<X.ReadHashtagsTocResponse> {
        return this.hashtagsDomain.readHashtagsToc(params);
    }

    updateHashtag(hashtagId: any, body: X.UpdateHashtagBody): Observable<X.UpdateHashtagResponse> {
        return this.hashtagsDomain.updateHashtag(hashtagId, body);
    }

    /**
     * Internal Management domain
     */
    private _internalDomain: X.InternalDomain;
    
    public get internalDomain(): X.InternalDomain {
        if (!this._internalDomain) {
            this._internalDomain = this.injector.get(X.InternalDomain);
        }
    
        return this._internalDomain;
    }

    updateAccountTypeAsAdmin(body: X.UpdateAccountTypeAsAdminBody): Observable<X.UpdateAccountTypeAsAdminResponse> {
        return this.internalDomain.updateAccountTypeAsAdmin(body);
    }

    /**
     * Invoice Management domain
     */
    private _invoicesDomain: X.InvoicesDomain;
    
    public get invoicesDomain(): X.InvoicesDomain {
        if (!this._invoicesDomain) {
            this._invoicesDomain = this.injector.get(X.InvoicesDomain);
        }
    
        return this._invoicesDomain;
    }

    bulkReadInvoices(): DataState<X.BulkReadInvoicesResponse> {
        return this.invoicesDomain.bulkReadInvoices();
    }

    calculateDebt(): DataState<X.CalculateDebtResponse> {
        return this.invoicesDomain.calculateDebt();
    }

    /**
     * Links Management domain
     */
    private _linksDomain: X.LinksDomain;
    
    public get linksDomain(): X.LinksDomain {
        if (!this._linksDomain) {
            this._linksDomain = this.injector.get(X.LinksDomain);
        }
    
        return this._linksDomain;
    }

    deleteLink(fromCardId: any, toCardId: any): Observable<X.DeleteLinkResponse> {
        return this.linksDomain.deleteLink(fromCardId, toCardId);
    }

    readOrCreateLink(body: X.ReadOrCreateLinkBody): Observable<X.ReadOrCreateLinkResponse> {
        return this.linksDomain.readOrCreateLink(body);
    }

    /**
     * MediaItems Management domain
     */
    private _mediaitemsDomain: X.MediaitemsDomain;
    
    public get mediaitemsDomain(): X.MediaitemsDomain {
        if (!this._mediaitemsDomain) {
            this._mediaitemsDomain = this.injector.get(X.MediaitemsDomain);
        }
    
        return this._mediaitemsDomain;
    }

    bulkReadMediaitems(params: X.BulkReadMediaitemsQuery): DataState<X.BulkReadMediaitemsResponse> {
        return this.mediaitemsDomain.bulkReadMediaitems(params);
    }

    deleteMediaitem(mediaitemId: any, params: X.DeleteMediaitemQuery): Observable<X.DeleteMediaitemResponse> {
        return this.mediaitemsDomain.deleteMediaitem(mediaitemId, params);
    }

    readMediaitem(mediaitemId: any): DataState<X.ReadMediaitemResponse> {
        return this.mediaitemsDomain.readMediaitem(mediaitemId);
    }

    readMediaitemByProcessId(processId: any): DataState<X.ReadMediaitemByProcessIdResponse> {
        return this.mediaitemsDomain.readMediaitemByProcessId(processId);
    }

    readOrCreateMediaitem(body: X.ReadOrCreateMediaitemBody): Observable<X.ReadOrCreateMediaitemResponse> {
        return this.mediaitemsDomain.readOrCreateMediaitem(body);
    }

    updateMediaitem(mediaitemId: any, body: X.UpdateMediaitemBody): Observable<X.UpdateMediaitemResponse> {
        return this.mediaitemsDomain.updateMediaitem(mediaitemId, body);
    }

    updateMediaitemRepresentation(mediaitemId: any, body: X.UpdateMediaitemRepresentationBody): Observable<X.UpdateMediaitemRepresentationResponse> {
        return this.mediaitemsDomain.updateMediaitemRepresentation(mediaitemId, body);
    }

    /**
     * Notification Management domain
     */
    private _notificationsDomain: X.NotificationsDomain;
    
    public get notificationsDomain(): X.NotificationsDomain {
        if (!this._notificationsDomain) {
            this._notificationsDomain = this.injector.get(X.NotificationsDomain);
        }
    
        return this._notificationsDomain;
    }

    acknowledgeNotification(notificationId: any): Observable<X.AcknowledgeNotificationResponse> {
        return this.notificationsDomain.acknowledgeNotification(notificationId);
    }

    bulkReadNotifications(params: X.BulkReadNotificationsQuery): DataState<X.BulkReadNotificationsResponse> {
        return this.notificationsDomain.bulkReadNotifications(params);
    }

    /**
     * Paths Management domain
     */
    private _pathsDomain: X.PathsDomain;
    
    public get pathsDomain(): X.PathsDomain {
        if (!this._pathsDomain) {
            this._pathsDomain = this.injector.get(X.PathsDomain);
        }
    
        return this._pathsDomain;
    }

    bulkDeletePaths(params: X.BulkDeletePathsQuery): Observable<X.BulkDeletePathsResponse> {
        return this.pathsDomain.bulkDeletePaths(params);
    }

    bulkReadPaths(params: X.BulkReadPathsQuery): DataState<X.BulkReadPathsResponse> {
        return this.pathsDomain.bulkReadPaths(params);
    }

    createPath(body: X.CreatePathBody): Observable<X.CreatePathResponse> {
        return this.pathsDomain.createPath(body);
    }

    readPath(pathId: any): DataState<X.ReadPathResponse> {
        return this.pathsDomain.readPath(pathId);
    }

    updatePath(pathId: any, body: X.UpdatePathBody): Observable<X.UpdatePathResponse> {
        return this.pathsDomain.updatePath(pathId, body);
    }

    /**
     * Payment Cards Management domain
     */
    private _payment_cardsDomain: X.PaymentCardsDomain;
    
    public get payment_cardsDomain(): X.PaymentCardsDomain {
        if (!this._payment_cardsDomain) {
            this._payment_cardsDomain = this.injector.get(X.PaymentCardsDomain);
        }
    
        return this._payment_cardsDomain;
    }

    asDefaultMarkPaymentcard(paymentCardId: any): Observable<X.AsDefaultMarkPaymentcardResponse> {
        return this.payment_cardsDomain.asDefaultMarkPaymentcard(paymentCardId);
    }

    bulkReadPaymentcards(): DataState<X.BulkReadPaymentcardsResponse> {
        return this.payment_cardsDomain.bulkReadPaymentcards();
    }

    createPaymentcard(body: X.CreatePaymentcardBody): Observable<X.CreatePaymentcardResponse> {
        return this.payment_cardsDomain.createPaymentcard(body);
    }

    deletePaymentcard(paymentCardId: any): Observable<X.DeletePaymentcardResponse> {
        return this.payment_cardsDomain.deletePaymentcard(paymentCardId);
    }

    payWithDefaultPaymentCard(body: X.PayWithDefaultPaymentCardBody): Observable<X.PayWithDefaultPaymentCardResponse> {
        return this.payment_cardsDomain.payWithDefaultPaymentCard(body);
    }

    renderPaymentCardWidget(): DataState<X.RenderPaymentCardWidgetResponse> {
        return this.payment_cardsDomain.renderPaymentCardWidget();
    }

    /**
     * Payments Management domain
     */
    private _paymentsDomain: X.PaymentsDomain;
    
    public get paymentsDomain(): X.PaymentsDomain {
        if (!this._paymentsDomain) {
            this._paymentsDomain = this.injector.get(X.PaymentsDomain);
        }
    
        return this._paymentsDomain;
    }

    updatePaymentStatus(body: X.UpdatePaymentStatusBody): Observable<X.UpdatePaymentStatusResponse> {
        return this.paymentsDomain.updatePaymentStatus(body);
    }

    /**
     * Recall Management domain
     */
    private _recallDomain: X.RecallDomain;
    
    public get recallDomain(): X.RecallDomain {
        if (!this._recallDomain) {
            this._recallDomain = this.injector.get(X.RecallDomain);
        }
    
        return this._recallDomain;
    }

    createRecallSession(body: X.CreateRecallSessionBody): Observable<X.CreateRecallSessionResponse> {
        return this.recallDomain.createRecallSession(body);
    }

    readRecallSummary(): DataState<X.ReadRecallSummaryResponse> {
        return this.recallDomain.readRecallSummary();
    }

    /**
     * Subscription Management domain
     */
    private _subscriptionsDomain: X.SubscriptionsDomain;
    
    public get subscriptionsDomain(): X.SubscriptionsDomain {
        if (!this._subscriptionsDomain) {
            this._subscriptionsDomain = this.injector.get(X.SubscriptionsDomain);
        }
    
        return this._subscriptionsDomain;
    }

    changeSubscription(body: X.ChangeSubscriptionBody): Observable<X.ChangeSubscriptionResponse> {
        return this.subscriptionsDomain.changeSubscription(body);
    }

    /**
     * Tasks Management domain
     */
    private _tasksDomain: X.TasksDomain;
    
    public get tasksDomain(): X.TasksDomain {
        if (!this._tasksDomain) {
            this._tasksDomain = this.injector.get(X.TasksDomain);
        }
    
        return this._tasksDomain;
    }

    bulkReadTasks(params: X.BulkReadTasksQuery): DataState<X.BulkReadTasksResponse> {
        return this.tasksDomain.bulkReadTasks(params);
    }

    bulkReadTaskBins(params: X.BulkReadTaskBinsQuery): DataState<X.BulkReadTaskBinsResponse> {
        return this.tasksDomain.bulkReadTaskBins(params);
    }

    /**
     * Words Management domain
     */
    private _wordsDomain: X.WordsDomain;
    
    public get wordsDomain(): X.WordsDomain {
        if (!this._wordsDomain) {
            this._wordsDomain = this.injector.get(X.WordsDomain);
        }
    
        return this._wordsDomain;
    }

    bulkReadWords(params: X.BulkReadWordsQuery): DataState<X.BulkReadWordsResponse> {
        return this.wordsDomain.bulkReadWords(params);
    }

}