/**
 * Fragment Hashtags Management Domain
 */
import { Injectable } from '@angular/core';
import { filter } from 'rxjs/operators';
import { Observable } from 'rxjs';
import * as _ from 'underscore';

import { ClientService, DataState } from '../../services/client.service';
import * as X from './fragment_hashtags.models';

@Injectable()
export class FragmentHashtagsDomain {
    constructor(private client: ClientService) {}

    /**
     * List Hashtags
     * -------------
     *
     * List Hashtags
     */
    public bulkReadFragmentHashtags(params: X.BulkReadFragmentHashtagsQuery): DataState<X.BulkReadFragmentHashtagsResponse> {
        return this.client.getDataState<X.BulkReadFragmentHashtagsResponse>('/fragments/hashtags/', { params });
    }

    /**
     * List Published Hashtags
     * -------------
     *
     * List Published Hashtags
     */
    public bulkReadPublishedFragmentHashtags(params: X.BulkReadPublishedFragmentHashtagsQuery): DataState<X.BulkReadPublishedFragmentHashtagsResponse> {
        return this.client.getDataState<X.BulkReadPublishedFragmentHashtagsResponse>('/fragments/hashtags/published/', { params });
    }

}