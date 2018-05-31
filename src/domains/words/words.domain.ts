/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */

/**
 * Words Management Domain
 */
import { Injectable } from '@angular/core';
import { filter } from 'rxjs/operators';
import { Observable } from 'rxjs';
import * as _ from 'underscore';

import { ClientService } from '../../services/client.service';
import { DataState } from '../../services/client.interface';

import * as X from './words.models';

@Injectable()
export class WordsDomain {
    constructor(private client: ClientService) {}

    /**
     * List Words
     * -------------
     *
     * List Words by first character. It allows one to fetch list of words by first character.
     */
    public bulkReadWords(params: X.BulkReadWordsQuery): DataState<X.BulkReadWordsResponseEntity[]> {
        return this.client.getDataState<X.BulkReadWordsResponseEntity[]>('/words/', { params, responseMap: 'data', authorizationRequired: true });
    }

}