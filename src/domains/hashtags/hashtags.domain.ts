/**
 * Hashtags Management Domain
 */
import { Injectable } from '@angular/core';
import { filter } from 'rxjs/operators';
import { Observable } from 'rxjs';
import * as _ from 'underscore';

import { ClientService, DataState } from '../../services/client.service';
import * as X from './hashtags.models';

@Injectable()
export class HashtagsDomain {
    constructor(private client: ClientService) {}

    /**
     * List Hashtags
     * -------------
     *
     * Enables one to list a series of Hashtag instances. It accepts various query parameters such as: - `limit` - `offset` - `first_character`
     */
    public bulkReadHashtags(params: X.BulkReadHashtagsQuery): DataState<X.BulkReadHashtagsResponse> {
        return this.client.getDataState<X.BulkReadHashtagsResponse>('/hashtags/', { params });
    }

    /**
     * Creating a single Hashtag
     * -------------
     *
     * Enables one to create a single Hashtag instance.
     */
    public createHashtag(body: X.CreateHashtagBody): Observable<X.CreateHashtagResponse> {
        return this.client
            .post<X.CreateHashtagResponse>('/hashtags/', body)
            .pipe(filter(x => !_.isEmpty(x)));
    }

    /**
     * Removing a single Hashtag
     * -------------
     *
     * Enables one to detach a single Hashtag instance from a list cards given by `card_ids`.
     */
    public deleteHashtag(hashtagId: any, params: X.DeleteHashtagQuery): Observable<X.DeleteHashtagResponse> {
        return this.client
            .delete<X.DeleteHashtagResponse>(`/hashtags/${hashtagId}`, { params })
            .pipe(filter(x => !_.isEmpty(x)));
    }

    /**
     * List Hashtags TOC
     * -------------
     *
     * Enables one to list Hashtags Table of Contents made out of Hashtags. Note: Currently this endpoint returns only a flat list of hashtags with the count of Cards with which they're attached to. In the future though one could propose a mechanism which could calculate hierarchy between those hashtags (parent - child relationships) and ordering based on the knowledge grid topology. It accepts various query parameters such as: - `limit` - `offset`
     */
    public readHashtagsToc(params: X.ReadHashtagsTocQuery): DataState<X.ReadHashtagsTocResponse> {
        return this.client.getDataState<X.ReadHashtagsTocResponse>('/hashtags/toc', { params });
    }

    /**
     * Updating a single Hashtag
     * -------------
     *
     * Enables one to update a single Hashtag instance with a list of `card_ids` to which it should get attached to.
     */
    public updateHashtag(hashtagId: any, body: X.UpdateHashtagBody): Observable<X.UpdateHashtagResponse> {
        return this.client
            .put<X.UpdateHashtagResponse>(`/hashtags/${hashtagId}`, body)
            .pipe(filter(x => !_.isEmpty(x)));
    }

}