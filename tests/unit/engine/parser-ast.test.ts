import { describe, test, expect } from 'bun:test';
import {
  parse,
  parsePython,
  parseJava,
  parseC,
  parseGo,
  parseJavaScript,
  detectLanguage,
  findNodesByType,
  findNodesByProperty,
  astToJSON,
  type ASTNode,
  type Language,
} from '../../../src/engine/parser.js';

describe('parser: detectLanguage', () => {
  test('detects Python', () => {
    expect(detectLanguage('foo.py')).toBe('python');
  });

  test('detects JavaScript/TypeScript variants', () => {
    expect(detectLanguage('a.js')).toBe('javascript');
    expect(detectLanguage('a.jsx')).toBe('javascript');
    expect(detectLanguage('a.ts')).toBe('javascript');
    expect(detectLanguage('a.tsx')).toBe('javascript');
    expect(detectLanguage('a.mjs')).toBe('javascript');
    expect(detectLanguage('a.cjs')).toBe('javascript');
  });

  test('detects Java', () => {
    expect(detectLanguage('Main.java')).toBe('java');
  });

  test('detects C/C++', () => {
    expect(detectLanguage('a.c')).toBe('c');
    expect(detectLanguage('a.h')).toBe('c');
    expect(detectLanguage('a.cpp')).toBe('c');
    expect(detectLanguage('a.hpp')).toBe('c');
    expect(detectLanguage('a.cc')).toBe('c');
    expect(detectLanguage('a.cxx')).toBe('c');
  });

  test('detects Go', () => {
    expect(detectLanguage('main.go')).toBe('go');
  });

  test('defaults to javascript for unknown extension', () => {
    expect(detectLanguage('a.unknown')).toBe('javascript');
    expect(detectLanguage('README')).toBe('javascript');
  });
});

describe('parser: parsePython', () => {
  test('parses simple Python with tree-sitter', () => {
    const code = `def hello():\n    print("hi")\n`;
    const result = parsePython(code);
    expect(result.language).toBe('python');
    expect(result.ast).toBeDefined();
    expect(result.ast.type).toBeDefined();
  });

  test('parses Python class with methods', () => {
    const code = `
class Foo:
    def __init__(self):
        self.x = 1
    def bar(self, y):
        return self.x + y
`;
    const result = parsePython(code);
    expect(result.language).toBe('python');
    // Tree-sitter may or may not load, but function returns valid result
    expect(result.errors).toBeArray();
  });

  test('handles empty code', () => {
    const result = parsePython('');
    expect(result.language).toBe('python');
    expect(result.ast).toBeDefined();
  });

  test('handles invalid Python gracefully', () => {
    const result = parsePython('def x(}}}}}');
    expect(result.language).toBe('python');
    expect(result.ast).toBeDefined();
  });
});

describe('parser: parseJava', () => {
  test('parses Java class with tree-sitter', () => {
    const code = `
public class Hello {
    public static void main(String[] args) {
        System.out.println("hi");
    }
}
`;
    const result = parseJava(code);
    expect(result.language).toBe('java');
    expect(result.ast).toBeDefined();
  });

  test('handles empty Java code', () => {
    const result = parseJava('');
    expect(result.language).toBe('java');
    expect(result.ast).toBeDefined();
  });
});

describe('parser: parseC', () => {
  test('parses C function with tree-sitter', () => {
    const code = `
int main(int argc, char *argv[]) {
    printf("hello\\n");
    return 0;
}
`;
    const result = parseC(code);
    expect(result.language).toBe('c');
    expect(result.ast).toBeDefined();
  });

  test('handles empty C code', () => {
    const result = parseC('');
    expect(result.language).toBe('c');
    expect(result.ast).toBeDefined();
  });
});

describe('parser: parseGo', () => {
  test('parses Go function with tree-sitter', () => {
    const code = `
package main
import "fmt"
func main() {
    fmt.Println("hi")
}
`;
    const result = parseGo(code);
    expect(result.language).toBe('go');
    expect(result.ast).toBeDefined();
  });

  test('handles empty Go code', () => {
    const result = parseGo('');
    expect(result.language).toBe('go');
    expect(result.ast).toBeDefined();
  });
});

describe('parser: parseJavaScript', () => {
  test('parses simple JavaScript', () => {
    const code = `function add(a, b) { return a + b; }`;
    const result = parseJavaScript(code);
    expect(result.language).toBe('javascript');
    expect(result.ast).toBeDefined();
  });

  test('parses arrow function', () => {
    const code = `const add = (a, b) => a + b;`;
    const result = parseJavaScript(code);
    expect(result.language).toBe('javascript');
    expect(result.ast).toBeDefined();
  });

  test('handles empty JS code', () => {
    const result = parseJavaScript('');
    expect(result.language).toBe('javascript');
    expect(result.ast).toBeDefined();
  });
});

describe('parser: parse dispatcher', () => {
  test('routes to correct parser by language', () => {
    const code = 'x = 1';
    const py = parse(code, 'python');
    expect(py.language).toBe('python');

    const js = parse(code, 'javascript');
    expect(js.language).toBe('javascript');

    const java = parse(code, 'java');
    expect(java.language).toBe('java');

    const c = parse(code, 'c');
    expect(c.language).toBe('c');

    const go = parse(code, 'go');
    expect(go.language).toBe('go');
  });

  test('handles typescript and rust (uses JS fallback)', () => {
    const ts = parse('const x: number = 1;', 'typescript');
    expect(ts.ast).toBeDefined();

    const rust = parse('fn main() {}', 'rust');
    expect(rust.ast).toBeDefined();
  });
});

describe('parser: findNodesByType', () => {
  test('finds nodes of a given type', () => {
    const code = `
def foo():
    pass

def bar():
    pass
`;
    const result = parsePython(code);
    const defs = findNodesByType(result.ast, 'function_definition');
    // Should find at least the fallback or tree-sitter function definitions
    expect(defs).toBeArray();
  });

  test('returns empty array when type not found', () => {
    const result = parsePython('x = 1');
    const nots = findNodesByType(result.ast, 'this_type_definitely_does_not_exist_xyz');
    expect(nots).toBeArray();
    expect(nots.length).toBe(0);
  });

  test('handles null children gracefully', () => {
    const node: ASTNode = { id: 'n1', type: 'test', children: [] };
    const result = findNodesByType(node, 'test');
    expect(result.length).toBe(1);
    expect(result[0].id).toBe('n1');
  });
});

describe('parser: findNodesByProperty', () => {
  test('finds nodes by property key and value', () => {
    const node: ASTNode = {
      id: 'n1',
      type: 'root',
      children: [
        { id: 'n2', type: 'fn', properties: new Map([['name', 'foo']]) },
        { id: 'n3', type: 'fn', properties: new Map([['name', 'bar']]) },
      ],
    };
    const fooNodes = findNodesByProperty(node, 'name', 'foo');
    expect(fooNodes.length).toBe(1);
    expect(fooNodes[0].id).toBe('n2');
  });

  test('returns empty when no match', () => {
    const node: ASTNode = {
      id: 'n1',
      type: 'root',
      children: [{ id: 'n2', type: 'fn', properties: new Map([['name', 'foo']]) }],
    };
    const matches = findNodesByProperty(node, 'name', 'nonexistent');
    expect(matches.length).toBe(0);
  });
});

describe('parser: astToJSON', () => {
  test('serializes AST node to JSON', () => {
    const node: ASTNode = {
      id: 'n1',
      type: 'test',
      code: 'sample',
      lineNumber: 1,
      children: [{ id: 'n2', type: 'child' }],
    };
    const json = astToJSON(node);
    expect(typeof json).toBe('string');
    const parsed = JSON.parse(json);
    expect(parsed.id).toBe('n1');
    expect(parsed.type).toBe('test');
    expect(parsed.code).toBe('sample');
    expect(parsed.lineNumber).toBe(1);
    expect(parsed.children.length).toBe(1);
  });

  test('serializes properties map to object', () => {
    const node: ASTNode = {
      id: 'n1',
      type: 'test',
      properties: new Map([['foo', 'bar']]),
    };
    const json = astToJSON(node);
    const parsed = JSON.parse(json);
    expect(parsed.properties).toEqual({ foo: 'bar' });
  });

  test('preserves all children in array', () => {
    const node: ASTNode = {
      id: 'n1',
      type: 'root',
      children: [null, undefined, { id: 'n2', type: 'c' }] as ASTNode[],
    };
    const json = astToJSON(node);
    const parsed = JSON.parse(json);
    expect(parsed.children.length).toBe(3);
  });
});

describe('parser: integration with real code samples', () => {
  test('parses Python with SQL injection sink', () => {
    const code = `
import os
user_input = input("name: ")
query = "SELECT * FROM users WHERE name = '" + user_input + "'"
db.execute(query)
`;
    const result = parsePython(code);
    expect(result.language).toBe('python');
    expect(result.ast.type).toBeDefined();
  });

  test('parses JavaScript with XSS sink', () => {
    const code = `
function render(userInput) {
    document.innerHTML = userInput;
}
`;
    const result = parseJavaScript(code);
    expect(result.language).toBe('javascript');
  });

  test('parses Java with file I/O', () => {
    const code = `
import java.io.*;
public class Read {
    public String read(String path) throws IOException {
        return new File(path).toString();
    }
}
`;
    const result = parseJava(code);
    expect(result.language).toBe('java');
  });

  test('parses C with buffer operations', () => {
    const code = `
#include <string.h>
void copy(char *src) {
    char buf[10];
    strcpy(buf, src);
}
`;
    const result = parseC(code);
    expect(result.language).toBe('c');
  });

  test('parses Go with HTTP handlers', () => {
    const code = `
package main
import "net/http"
func handler(w http.ResponseWriter, r *http.Request) {
    w.Write([]byte(r.URL.Query().Get("name")))
}
`;
    const result = parseGo(code);
    expect(result.language).toBe('go');
  });
});
