/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */
/**
 * Invoice Management Domain Models
 */
/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/69bb55b04713846fc3aa1a1c300a8a9ed207b2d3/cosphere_auth_service/payment/serializers/invoice.py/#lines-53
 */
export var BulkReadInvoicesResponseCurrency;
(function (BulkReadInvoicesResponseCurrency) {
    BulkReadInvoicesResponseCurrency["PLN"] = "PLN";
})(BulkReadInvoicesResponseCurrency || (BulkReadInvoicesResponseCurrency = {}));
export var BulkReadInvoicesResponseProductType;
(function (BulkReadInvoicesResponseProductType) {
    BulkReadInvoicesResponseProductType["DONATION"] = "DONATION";
    BulkReadInvoicesResponseProductType["SUBSCRIPTION_LEARNER_MONTHLY"] = "SUBSCRIPTION_LEARNER_MONTHLY";
    BulkReadInvoicesResponseProductType["SUBSCRIPTION_LEARNER_YEARLY"] = "SUBSCRIPTION_LEARNER_YEARLY";
    BulkReadInvoicesResponseProductType["SUBSCRIPTION_MENTOR_MONTHLY"] = "SUBSCRIPTION_MENTOR_MONTHLY";
    BulkReadInvoicesResponseProductType["SUBSCRIPTION_MENTOR_YEARLY"] = "SUBSCRIPTION_MENTOR_YEARLY";
})(BulkReadInvoicesResponseProductType || (BulkReadInvoicesResponseProductType = {}));

//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW52b2ljZXMubW9kZWxzLmpzIiwic291cmNlUm9vdCI6Im5nOi8vQGNvc3BoZXJlL2NsaWVudC8iLCJzb3VyY2VzIjpbImRvbWFpbnMvaW52b2ljZXMvaW52b2ljZXMubW9kZWxzLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiJBQUFBOzs7SUFHSTtBQUVKOztHQUVHO0FBRUg7O0dBRUc7QUFFSCxNQUFNLENBQU4sSUFBWSxnQ0FFWDtBQUZELFdBQVksZ0NBQWdDO0lBQ3hDLCtDQUFXLENBQUE7QUFDZixDQUFDLEVBRlcsZ0NBQWdDLEtBQWhDLGdDQUFnQyxRQUUzQztBQUVELE1BQU0sQ0FBTixJQUFZLG1DQU1YO0FBTkQsV0FBWSxtQ0FBbUM7SUFDM0MsNERBQXFCLENBQUE7SUFDckIsb0dBQTZELENBQUE7SUFDN0Qsa0dBQTJELENBQUE7SUFDM0Qsa0dBQTJELENBQUE7SUFDM0QsZ0dBQXlELENBQUE7QUFDN0QsQ0FBQyxFQU5XLG1DQUFtQyxLQUFuQyxtQ0FBbUMsUUFNOUMiLCJzb3VyY2VzQ29udGVudCI6WyIvKipcbiAgKiBUSElTIEZJTEUgV0FTIEFVVE9HRU5FUkFURUQsIEFMTCBNQU5VQUwgQ0hBTkdFUyBDQU4gQkVcbiAgKiBPVkVSV1JJVFRFTlxuICAqL1xuXG4vKipcbiAqIEludm9pY2UgTWFuYWdlbWVudCBEb21haW4gTW9kZWxzXG4gKi9cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWF1dGgtc2VydmljZS9zcmMvNjliYjU1YjA0NzEzODQ2ZmMzYWExYTFjMzAwYThhOWVkMjA3YjJkMy9jb3NwaGVyZV9hdXRoX3NlcnZpY2UvcGF5bWVudC9zZXJpYWxpemVycy9pbnZvaWNlLnB5LyNsaW5lcy01M1xuICovXG5cbmV4cG9ydCBlbnVtIEJ1bGtSZWFkSW52b2ljZXNSZXNwb25zZUN1cnJlbmN5IHtcbiAgICBQTE4gPSAnUExOJyxcbn1cblxuZXhwb3J0IGVudW0gQnVsa1JlYWRJbnZvaWNlc1Jlc3BvbnNlUHJvZHVjdFR5cGUge1xuICAgIERPTkFUSU9OID0gJ0RPTkFUSU9OJyxcbiAgICBTVUJTQ1JJUFRJT05fTEVBUk5FUl9NT05USExZID0gJ1NVQlNDUklQVElPTl9MRUFSTkVSX01PTlRITFknLFxuICAgIFNVQlNDUklQVElPTl9MRUFSTkVSX1lFQVJMWSA9ICdTVUJTQ1JJUFRJT05fTEVBUk5FUl9ZRUFSTFknLFxuICAgIFNVQlNDUklQVElPTl9NRU5UT1JfTU9OVEhMWSA9ICdTVUJTQ1JJUFRJT05fTUVOVE9SX01PTlRITFknLFxuICAgIFNVQlNDUklQVElPTl9NRU5UT1JfWUVBUkxZID0gJ1NVQlNDUklQVElPTl9NRU5UT1JfWUVBUkxZJyxcbn1cblxuZXhwb3J0IGludGVyZmFjZSBCdWxrUmVhZEludm9pY2VzUmVzcG9uc2VFbnRpdHkge1xuICAgIGFtb3VudDogc3RyaW5nO1xuICAgIGNyZWF0ZWRfdGltZXN0YW1wOiBudW1iZXI7XG4gICAgY3VycmVuY3k/OiBzdHJpbmc7XG4gICAgZGlzcGxheV9hbW91bnQ6IHN0cmluZztcbiAgICBpZD86IG51bWJlcjtcbiAgICBpc19leHRlbnNpb24/OiBib29sZWFuO1xuICAgIHBhaWRfdGlsbF90aW1lc3RhbXA6IG51bWJlcjtcbiAgICBwcm9kdWN0OiB7XG4gICAgICAgIGN1cnJlbmN5PzogQnVsa1JlYWRJbnZvaWNlc1Jlc3BvbnNlQ3VycmVuY3k7XG4gICAgICAgIGRpc3BsYXlfcHJpY2U6IHN0cmluZztcbiAgICAgICAgbmFtZTogc3RyaW5nO1xuICAgICAgICBwcmljZT86IHN0cmluZztcbiAgICAgICAgcHJvZHVjdF90eXBlOiBCdWxrUmVhZEludm9pY2VzUmVzcG9uc2VQcm9kdWN0VHlwZTtcbiAgICB9O1xuICAgIHN1cnBsdXNfYW1vdW50Pzogc3RyaW5nO1xuICAgIHN1cnBsdXNfY3VycmVuY3k/OiBzdHJpbmc7XG4gICAgdmFsaWRfdGlsbF90aW1lc3RhbXA6IG51bWJlcjtcbn1cblxuZXhwb3J0IGludGVyZmFjZSBCdWxrUmVhZEludm9pY2VzUmVzcG9uc2Uge1xuICAgIGludm9pY2VzOiBCdWxrUmVhZEludm9pY2VzUmVzcG9uc2VFbnRpdHlbXTtcbn1cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWF1dGgtc2VydmljZS9zcmMvNjliYjU1YjA0NzEzODQ2ZmMzYWExYTFjMzAwYThhOWVkMjA3YjJkMy9jb3NwaGVyZV9hdXRoX3NlcnZpY2UvcGF5bWVudC92aWV3cy9pbnZvaWNlLnB5LyNsaW5lcy01MVxuICovXG5cbmV4cG9ydCBpbnRlcmZhY2UgQ2FsY3VsYXRlRGVidFJlc3BvbnNlIHtcbiAgICBhdF9fY29tbWFuZHM6IE9iamVjdDtcbiAgICBjdXJyZW5jeTogc3RyaW5nO1xuICAgIGRpc3BsYXlfb3dlczogc3RyaW5nO1xuICAgIG93ZXM6IG51bWJlcjtcbn0iXX0=