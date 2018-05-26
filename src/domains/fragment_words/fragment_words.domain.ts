/**
 * Fragment Words Management Domain
 */
import { Injectable } from '@angular/core';
import { filter } from 'rxjs/operators';
import { Observable } from 'rxjs';
import * as _ from 'underscore';

import { ClientService } from '../../services/client.service';
import { DataState } from '../../services/client.interface';
import * as X from './fragment_words.models';

@Injectable()
export class FragmentWordsDomain {
    constructor(private client: ClientService) {}

    /**
     * List Words
     * -------------
     *
     * List Words
     */
    public bulkReadFragmentWords(params: X.BulkReadFragmentWordsQuery): DataState<X.BulkReadFragmentWordsResponse> {
        return this.client.getDataState<X.BulkReadFragmentWordsResponse>('/fragments/words/', { params });
    }

    /**
     * List Published Words
     * -------------
     *
     * List Published Words
     */
    public bulkReadPublishedFragmentWords(params: X.BulkReadPublishedFragmentWordsQuery): DataState<X.BulkReadPublishedFragmentWordsResponse> {
        return this.client.getDataState<X.BulkReadPublishedFragmentWordsResponse>('/fragments/words/published/', { params });
    }

}