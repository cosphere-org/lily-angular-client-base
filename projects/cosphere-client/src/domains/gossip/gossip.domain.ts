/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */

/**
 * Gossip Commands Management Domain
 */
import { Injectable } from '@angular/core';
import { filter } from 'rxjs/operators';
import { Observable } from 'rxjs';
import * as _ from 'underscore';

import { ClientService } from '../../services/client.service';
import { DataState } from '../../services/client.interface';

import * as X from './gossip.models';

@Injectable()
export class GossipDomain {
    constructor(private client: ClientService) {}

    /**
     * Bulk Read all supported spoken languages
     */
    public bulkReadSpeechLanguages(): DataState<X.BulkReadSpeechLanguagesResponseEntity[]> {
        return this.client.getDataState<X.BulkReadSpeechLanguagesResponseEntity[]>('/gossip/speech/languages/', { responseMap: 'data', authorizationRequired: true });
    }
    
    public bulkReadSpeechLanguages2(): Observable<X.BulkReadSpeechLanguagesResponseEntity[]> {
        return this.client.get<X.BulkReadSpeechLanguagesResponseEntity[]>('/gossip/speech/languages/', { responseMap: 'data', authorizationRequired: true });
    }

    /**
     * Bulk Read all supported voice languages
     */
    public bulkReadTextLanguages(): DataState<X.BulkReadTextLanguagesResponseEntity[]> {
        return this.client.getDataState<X.BulkReadTextLanguagesResponseEntity[]>('/gossip/text/languages/', { responseMap: 'data', authorizationRequired: true });
    }
    
    public bulkReadTextLanguages2(): Observable<X.BulkReadTextLanguagesResponseEntity[]> {
        return this.client.get<X.BulkReadTextLanguagesResponseEntity[]>('/gossip/text/languages/', { responseMap: 'data', authorizationRequired: true });
    }

    /**
     * Detect spoken language
     */
    public detectSpeechLanguages(body: X.DetectSpeechLanguagesBody): Observable<X.DetectSpeechLanguagesResponse> {
        return this.client
            .post<X.DetectSpeechLanguagesResponse>('/gossip/speech/detect_languages/', body, { authorizationRequired: true })
            .pipe(filter(x => !_.isEmpty(x)));
    }

    /**
     * Detect written language
     */
    public detectTextLanguages(body: X.DetectTextLanguagesBody): Observable<X.DetectTextLanguagesResponse> {
        return this.client
            .post<X.DetectTextLanguagesResponse>('/gossip/text/detect_languages/', body, { authorizationRequired: true })
            .pipe(filter(x => !_.isEmpty(x)));
    }

}