import { GraphQLScalarType, GraphQLError } from 'graphql';
import { Kind } from 'graphql/language';
import { ValueNode } from 'graphql/language/ast';
import * as validator from 'validator';


/**
 * Check email address
 * @param value
 * @returns {string}
 */
const checkEmailAddress = (value: any): string => {

  // Check value
  if (typeof value !== 'string' || !validator.isEmail(value)) {
    const message = `EmailAddress can't represent non-email-address value: ${value}`;
    throw new TypeError(message);
  }

  // Return date
  return value;
};

/**
 * Date scalar type for GraphQL
 * Inspired by https://github.com/adriano-di-giovanni/graphql-scalars/blob/master/src/GraphQLDate.js
 *
 * @type {GraphQLScalarType}
 */
export const YosEmailAddressScalar = new GraphQLScalarType({

  /**
   * Name of the scalar
   */
  name: 'EmailAddress',

  /**
   * Description of the scalar
   */
  description: 'Email address',

  /**
   * Parse value from the client
   * @param value
   * @returns {any}
   */
  parseValue(value: any): any {
    return checkEmailAddress(value);
  },

  /**
   * Serialize value to the client
   * @param value
   * @returns {any}
   */
  serialize(value: any): any {
    return checkEmailAddress(value);
  },

  /**
   * Parse literal
   * @param valueNode
   * @returns {any}
   */
  parseLiteral(valueNode: ValueNode): any {

    // Init
    const {kind, value} = <any> valueNode;

    // Check data
    if (kind !== Kind.STRING || !validator.isEmail(value)) {
      throw new GraphQLError(`Expected email address value (string) but got: ${value}`, [valueNode]);
    }

    // Return value
    return value;
  }
});
