/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */
/**
 * Categories Management Domain
 */
import { Injectable } from '@angular/core';
import { ClientService } from '../../services/client.service';
var CategoriesDomain = /** @class */ (function () {
    function CategoriesDomain(client) {
        this.client = client;
    }
    /**
     * List Categories
     * -------------
     *
     * List Categories.
     */
    CategoriesDomain.prototype.bulkReadCategories = function () {
        return this.client.getDataState('/categories/', { responseMap: 'categories', authorizationRequired: true });
    };
    CategoriesDomain.prototype.bulkReadCategories2 = function () {
        return this.client.get('/categories/', { responseMap: 'categories', authorizationRequired: true });
    };
    CategoriesDomain.decorators = [
        { type: Injectable }
    ];
    /** @nocollapse */
    CategoriesDomain.ctorParameters = function () { return [
        { type: ClientService }
    ]; };
    return CategoriesDomain;
}());
export { CategoriesDomain };

//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiY2F0ZWdvcmllcy5kb21haW4uanMiLCJzb3VyY2VSb290Ijoibmc6Ly9AY29zcGhlcmUvY2xpZW50LyIsInNvdXJjZXMiOlsiZG9tYWlucy9jYXRlZ29yaWVzL2NhdGVnb3JpZXMuZG9tYWluLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiJBQUFBOzs7SUFHSTtBQUVKOztHQUVHO0FBQ0gsT0FBTyxFQUFFLFVBQVUsRUFBRSxNQUFNLGVBQWUsQ0FBQztBQUszQyxPQUFPLEVBQUUsYUFBYSxFQUFFLE1BQU0sK0JBQStCLENBQUM7QUFLOUQ7SUFFSSwwQkFBb0IsTUFBcUI7UUFBckIsV0FBTSxHQUFOLE1BQU0sQ0FBZTtJQUFHLENBQUM7SUFFN0M7Ozs7O09BS0c7SUFDSSw2Q0FBa0IsR0FBekI7UUFDSSxNQUFNLENBQUMsSUFBSSxDQUFDLE1BQU0sQ0FBQyxZQUFZLENBQXVDLGNBQWMsRUFBRSxFQUFFLFdBQVcsRUFBRSxZQUFZLEVBQUUscUJBQXFCLEVBQUUsSUFBSSxFQUFFLENBQUMsQ0FBQztJQUN0SixDQUFDO0lBRU0sOENBQW1CLEdBQTFCO1FBQ0ksTUFBTSxDQUFDLElBQUksQ0FBQyxNQUFNLENBQUMsR0FBRyxDQUF1QyxjQUFjLEVBQUUsRUFBRSxXQUFXLEVBQUUsWUFBWSxFQUFFLHFCQUFxQixFQUFFLElBQUksRUFBRSxDQUFDLENBQUM7SUFDN0ksQ0FBQzs7Z0JBaEJKLFVBQVU7Ozs7Z0JBTEYsYUFBYTs7SUF1QnRCLHVCQUFDO0NBQUEsQUFsQkQsSUFrQkM7U0FqQlksZ0JBQWdCIiwic291cmNlc0NvbnRlbnQiOlsiLyoqXG4gICogVEhJUyBGSUxFIFdBUyBBVVRPR0VORVJBVEVELCBBTEwgTUFOVUFMIENIQU5HRVMgQ0FOIEJFXG4gICogT1ZFUldSSVRURU5cbiAgKi9cblxuLyoqXG4gKiBDYXRlZ29yaWVzIE1hbmFnZW1lbnQgRG9tYWluXG4gKi9cbmltcG9ydCB7IEluamVjdGFibGUgfSBmcm9tICdAYW5ndWxhci9jb3JlJztcbmltcG9ydCB7IGZpbHRlciB9IGZyb20gJ3J4anMvb3BlcmF0b3JzJztcbmltcG9ydCB7IE9ic2VydmFibGUgfSBmcm9tICdyeGpzJztcbmltcG9ydCAqIGFzIF8gZnJvbSAndW5kZXJzY29yZSc7XG5cbmltcG9ydCB7IENsaWVudFNlcnZpY2UgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuc2VydmljZSc7XG5pbXBvcnQgeyBEYXRhU3RhdGUgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuaW50ZXJmYWNlJztcblxuaW1wb3J0ICogYXMgWCBmcm9tICcuL2NhdGVnb3JpZXMubW9kZWxzJztcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIENhdGVnb3JpZXNEb21haW4ge1xuICAgIGNvbnN0cnVjdG9yKHByaXZhdGUgY2xpZW50OiBDbGllbnRTZXJ2aWNlKSB7fVxuXG4gICAgLyoqXG4gICAgICogTGlzdCBDYXRlZ29yaWVzXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogTGlzdCBDYXRlZ29yaWVzLlxuICAgICAqL1xuICAgIHB1YmxpYyBidWxrUmVhZENhdGVnb3JpZXMoKTogRGF0YVN0YXRlPFguQnVsa1JlYWRDYXRlZ29yaWVzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0RGF0YVN0YXRlPFguQnVsa1JlYWRDYXRlZ29yaWVzUmVzcG9uc2VFbnRpdHlbXT4oJy9jYXRlZ29yaWVzLycsIHsgcmVzcG9uc2VNYXA6ICdjYXRlZ29yaWVzJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgYnVsa1JlYWRDYXRlZ29yaWVzMigpOiBPYnNlcnZhYmxlPFguQnVsa1JlYWRDYXRlZ29yaWVzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguQnVsa1JlYWRDYXRlZ29yaWVzUmVzcG9uc2VFbnRpdHlbXT4oJy9jYXRlZ29yaWVzLycsIHsgcmVzcG9uc2VNYXA6ICdjYXRlZ29yaWVzJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cblxufSJdfQ==