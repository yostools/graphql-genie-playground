/**
 * Controllers for core api
 */
export class ApiResolver {

  /**
   * Api controller
   * @param context
   */
  public static async api(context: any): Promise<any> {

    // Init
    const packageJson = require('../../package.json');
    const environment: string = process.env.NODE_ENV ? process.env.NODE_ENV : 'development';
    const name = packageJson.name;
    const version = packageJson.version;

    // Return data
    return {
      environment: environment,
      name: name,
      version: version,
      ipLookup: context.ipLookup
    };
  }
}
