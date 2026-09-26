package com.flowseal.tgwsproxy.core

/**
 * Small strict JSON reader: objects become maps, arrays lists, numbers Long or
 * Double. org.json is stubbed out in JVM unit tests, and the update code needs
 * to walk the GitHub release object properly (asset digests live per asset).
 */
object MiniJson {

    class ParseException(msg: String) : Exception(msg)

    @Throws(ParseException::class)
    fun parse(text: String): Any? {
        val p = Parser(text)
        p.ws()
        val v = p.value(0)
        p.ws()
        if (p.i != text.length) throw ParseException("trailing data at ${p.i}")
        return v
    }

    private class Parser(val s: String) {
        var i = 0

        fun ws() {
            while (i < s.length && s[i].isWhitespace()) i++
        }

        fun value(depth: Int): Any? {
            if (depth > 64) throw ParseException("too deep")
            if (i >= s.length) throw ParseException("unexpected end")
            return when (val c = s[i]) {
                '{' -> obj(depth)
                '[' -> arr(depth)
                '"' -> str()
                't' -> lit("true", true)
                'f' -> lit("false", false)
                'n' -> lit("null", null)
                else -> if (c == '-' || c.isDigit()) num() else throw ParseException("unexpected '$c' at $i")
            }
        }

        fun lit(word: String, v: Any?): Any? {
            if (!s.startsWith(word, i)) throw ParseException("bad literal at $i")
            i += word.length
            return v
        }

        fun num(): Any {
            val start = i
            if (s[i] == '-') i++
            while (i < s.length && (s[i].isDigit() || s[i] in ".eE+-")) i++
            val t = s.substring(start, i)
            return t.toLongOrNull() ?: t.toDoubleOrNull() ?: throw ParseException("bad number $t")
        }

        fun str(): String {
            i++ // opening quote
            val sb = StringBuilder()
            while (true) {
                if (i >= s.length) throw ParseException("unterminated string")
                val c = s[i++]
                when (c) {
                    '"' -> return sb.toString()
                    '\\' -> {
                        if (i >= s.length) throw ParseException("bad escape")
                        when (val e = s[i++]) {
                            'n' -> sb.append('\n')
                            'r' -> sb.append('\r')
                            't' -> sb.append('\t')
                            'b' -> sb.append('\b')
                            'f' -> sb.append('\u000C')
                            'u' -> {
                                if (i + 4 > s.length) throw ParseException("bad \\u escape")
                                val code = s.substring(i, i + 4).toIntOrNull(16)
                                    ?: throw ParseException("bad \\u escape")
                                sb.append(code.toChar())
                                i += 4
                            }
                            else -> sb.append(e)
                        }
                    }
                    else -> sb.append(c)
                }
            }
        }

        fun obj(depth: Int): Map<String, Any?> {
            i++
            val out = LinkedHashMap<String, Any?>()
            ws()
            if (i < s.length && s[i] == '}') {
                i++
                return out
            }
            while (true) {
                ws()
                if (i >= s.length || s[i] != '"') throw ParseException("expected key at $i")
                val k = str()
                ws()
                if (i >= s.length || s[i] != ':') throw ParseException("expected ':' at $i")
                i++
                ws()
                out[k] = value(depth + 1)
                ws()
                if (i >= s.length) throw ParseException("unterminated object")
                when (s[i++]) {
                    ',' -> continue
                    '}' -> return out
                    else -> throw ParseException("expected ',' or '}' at ${i - 1}")
                }
            }
        }

        fun arr(depth: Int): List<Any?> {
            i++
            val out = ArrayList<Any?>()
            ws()
            if (i < s.length && s[i] == ']') {
                i++
                return out
            }
            while (true) {
                ws()
                out.add(value(depth + 1))
                ws()
                if (i >= s.length) throw ParseException("unterminated array")
                when (s[i++]) {
                    ',' -> continue
                    ']' -> return out
                    else -> throw ParseException("expected ',' or ']' at ${i - 1}")
                }
            }
        }
    }
}
