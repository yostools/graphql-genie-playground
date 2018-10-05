import { GraphQLScalarType } from 'graphql';
import { GraphQLHelper } from '../helper/graphql.helper';

/**
 * Any scalar type for GraphQL
 * Inspired by https://github.com/taion/graphql-type-json
 *
 * @type {GraphQLScalarType}
 */
export const YosAnyScalar = new GraphQLScalarType({

  /**
   * Name of the scalar
   */
  name: 'Any',

  /**
   * Description of the scalar
   */
  description: 'The `Any` scalar represents JSON values as specified by ' +
    '[ECMA-404](http://www.ecma-international.org/publications/files/ECMA-ST/ECMA-404.pdf).',

  /**
   * Parse value from the client
   * @param value
   * @returns {any}
   */
  parseValue(value: any): any {
    return value;
  },

  /**
   * Serialize value to the client
   * @param value
   * @returns {any}
   */
  serialize(value: any): any {
    return value;
  },

  /**
   * Parse literal
   * @param valueNode
   * @param variables
   * @returns {any}
   */
  parseLiteral: GraphQLHelper.parseLiteral
});
