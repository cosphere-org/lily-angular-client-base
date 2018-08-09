import { Observable } from 'rxjs';
import { ClientService } from '../../services/client.service';
import { DataState } from '../../services/client.interface';
import * as X from './hashtags.models';
export declare class HashtagsDomain {
    private client;
    constructor(client: ClientService);
    /**
     * List Hashtags
     * -------------
     *
     * Enables one to list a series of Hashtag instances. It accepts various query parameters such as: - `limit` - `offset` - `first_character`
     */
    bulkReadHashtags(params: X.BulkReadHashtagsQuery): DataState<X.BulkReadHashtagsResponseEntity[]>;
    bulkReadHashtags2(params: X.BulkReadHashtagsQuery): Observable<X.BulkReadHashtagsResponseEntity[]>;
    /**
     * Creating a single Hashtag
     * -------------
     *
     * Enables one to create a single Hashtag instance.
     */
    createHashtag(body: X.CreateHashtagBody): Observable<X.CreateHashtagResponse>;
    /**
     * Removing a single Hashtag
     * -------------
     *
     * Enables one to detach a single Hashtag instance from a list cards given by `card_ids`.
     */
    deleteHashtag(hashtagId: any, params: X.DeleteHashtagQuery): Observable<X.DeleteHashtagResponse>;
    /**
     * List Hashtags TOC
     * -------------
     *
     * Enables one to list Hashtags Table of Contents made out of Hashtags. Note: Currently this endpoint returns only a flat list of hashtags with the count of Cards with which they're attached to. In the future though one could propose a mechanism which could calculate hierarchy between those hashtags (parent - child relationships) and ordering based on the knowledge grid topology. It accepts various query parameters such as: - `limit` - `offset`
     */
    readHashtagsToc(params: X.ReadHashtagsTocQuery): DataState<X.ReadHashtagsTocResponse>;
    readHashtagsToc2(params: X.ReadHashtagsTocQuery): Observable<X.ReadHashtagsTocResponse>;
    /**
     * Updating a single Hashtag
     * -------------
     *
     * Enables one to update a single Hashtag instance with a list of `card_ids` to which it should get attached to.
     */
    updateHashtag(hashtagId: any, body: X.UpdateHashtagBody): Observable<X.UpdateHashtagResponse>;
}
