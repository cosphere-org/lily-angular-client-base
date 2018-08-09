/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */

/**
 * Categories Management Domain
 */
import { Injectable } from '@angular/core';
import { filter } from 'rxjs/operators';
import { Observable } from 'rxjs';
import * as _ from 'underscore';

import { ClientService } from '../../services/client.service';
import { DataState } from '../../services/client.interface';

import * as X from './categories.models';

@Injectable()
export class CategoriesDomain {
    constructor(private client: ClientService) {}

    /**
     * List Categories
     * -------------
     *
     * List Categories.
     */
    public bulkReadCategories(): DataState<X.BulkReadCategoriesResponseEntity[]> {
        return this.client.getDataState<X.BulkReadCategoriesResponseEntity[]>('/categories/', { responseMap: 'categories', authorizationRequired: true });
    }
    
    public bulkReadCategories2(): Observable<X.BulkReadCategoriesResponseEntity[]> {
        return this.client.get<X.BulkReadCategoriesResponseEntity[]>('/categories/', { responseMap: 'categories', authorizationRequired: true });
    }

}