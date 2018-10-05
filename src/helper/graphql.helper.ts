import { Kind, ValueNode } from 'graphql';
import Maybe from 'graphql/tsutils/Maybe';

/**
 * Helper for GraphQL
 */
export class GraphQLHelper {

  /**
   * Parse literal
   * @param valueNode
   * @param variables
   * @returns {any}
   */
  public static parseLiteral(valueNode: ValueNode, variables?: Maybe<any>): any {
    switch (valueNode.kind) {
      case Kind.STRING:
      case Kind.BOOLEAN:
        return valueNode.value;
      case Kind.INT:
      case Kind.FLOAT:
        return parseFloat(valueNode.value);
      case Kind.OBJECT: {
        const value = Object.create(null);
        valueNode.fields.forEach(field => {
          value[field.name.value] = GraphQLHelper.parseLiteral(field.value, variables);
        });
        return value;
      }
      case Kind.LIST:
        return valueNode.values.map(n => GraphQLHelper.parseLiteral(n, variables));
      case Kind.NULL:
        return null;
      case Kind.VARIABLE: {
        const name = valueNode.name.value;
        return variables ? variables[name] : undefined;
      }
      default:
        return undefined;
    }
  }
}
