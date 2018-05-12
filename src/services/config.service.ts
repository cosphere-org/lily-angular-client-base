import { Injectable } from '@angular/core';

export interface Config {
  baseUrl: string;
  authToken?: string;
}

@Injectable()
export class ConfigService {
  constructor(public config: Config) {}
}
