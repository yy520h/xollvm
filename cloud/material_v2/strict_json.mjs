function fail(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}

export function parseStrictJsonObject(bytes, maximumBytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length > maximumBytes)
    fail('request_size_limit');
  const text = Buffer.from(bytes).toString('utf8');
  if (!Buffer.from(text, 'utf8').equals(Buffer.from(bytes))) fail('invalid_json');
  let position = 0;
  const whitespace = () => {
    while (position < text.length && /[\t\n\r ]/.test(text[position])) ++position;
  };
  const string = () => {
    const start = position;
    if (text[position++] !== '"') fail('invalid_json');
    while (position < text.length) {
      const current = text[position++];
      if (current === '"') {
        try { return JSON.parse(text.slice(start, position)); }
        catch { fail('invalid_json'); }
      }
      if (current === '\\') {
        const escape = text[position++];
        if (escape === 'u') {
          if (!/^[0-9a-fA-F]{4}$/.test(text.slice(position, position + 4))) fail('invalid_json');
          position += 4;
        } else if (!'"\\/bfnrt'.includes(escape ?? '')) fail('invalid_json');
      } else if (current.charCodeAt(0) < 0x20) fail('invalid_json');
    }
    fail('invalid_json');
  };

  const value = (depth = 0) => {
    if (depth > 8) fail('invalid_json');
    whitespace();
    if (text[position] === '"') return string();
    if (text[position] === '{') {
      ++position;
      whitespace();
      const object = Object.create(null);
      const keys = new Set();
      if (text[position] === '}') { ++position; return object; }
      while (true) {
        whitespace();
        const key = string();
        if (keys.has(key)) fail('invalid_json');
        keys.add(key);
        whitespace();
        if (text[position++] !== ':') fail('invalid_json');
        object[key] = value(depth + 1);
        whitespace();
        const separator = text[position++];
        if (separator === '}') return object;
        if (separator !== ',') fail('invalid_json');
      }
    }
    if (text[position] === '[') {
      ++position;
      whitespace();
      const array = [];
      if (text[position] === ']') { ++position; return array; }
      while (true) {
        array.push(value(depth + 1));
        whitespace();
        const separator = text[position++];
        if (separator === ']') return array;
        if (separator !== ',') fail('invalid_json');
      }
    }
    for (const [literal, result] of [['true', true], ['false', false], ['null', null]]) {
      if (text.startsWith(literal, position)) {
        position += literal.length;
        return result;
      }
    }
    const match = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(text.slice(position));
    if (match) {
      position += match[0].length;
      return Number(match[0]);
    }
    fail('invalid_json');
  };

  const result = value();
  whitespace();
  if (position !== text.length) fail('invalid_json');
  if (!result || typeof result !== 'object' || Array.isArray(result)) fail('invalid_json');
  return result;
}
