/*******************************************************************************
 * @file         TopoTraceJson.kt
 * @brief        Part of the TopoTrace agent module.
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-17
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

package com.topotrace.agent

/**
 * Tiny, dependency-free JSON encoder.
 *
 * TopoTrace's mobile report body is deliberately simple -- a handful of
 * string/number/boolean fields per category (see model.mobileReportRequest
 * on the server side) -- so this hand-rolled encoder is enough and avoids
 * pulling in org.json/Moshi/Gson just to serialize a few maps. It only
 * needs to handle what DeviceFacts ever produces: String, Boolean, Int,
 * Long, Double, null, List<Any?>, and Map<String, Any?> (arbitrarily
 * nested, though in practice TopoTrace's facts are flat field->value maps
 * one level inside a category).
 *
 * Not a general-purpose JSON library: no parsing (this agent never needs
 * to read JSON back, only send it), no streaming, no custom
 * serialization hooks. That's an intentional, narrow scope match to what
 * this agent actually does, the same "small allow-list, not a framework"
 * philosophy as the rest of TopoTrace's agents.
 *
 * Verified with a plain `kotlinc` (no Android SDK involved) -- see
 * agent/android/README.md's "What's actually verified" section.
 */
object TopoTraceJson {

    /** Encodes [value] as a JSON string. Unrecognized types fall back to their toString(),
     * quoted -- this keeps encode() total (never throws) rather than failing a whole report
     * over one unexpected field type. */
    fun encode(value: Any?): String {
        val sb = StringBuilder()
        writeValue(sb, value)
        return sb.toString()
    }

    /** Convenience for the common case: a map of category name -> field map, i.e. exactly
     * the shape mobileReportRequest.Facts expects. */
    fun encodeFacts(facts: Map<String, Map<String, Any?>>): String = encode(facts)

    private fun writeValue(sb: StringBuilder, value: Any?) {
        when (value) {
            null -> sb.append("null")
            is String -> writeString(sb, value)
            is Boolean -> sb.append(if (value) "true" else "false")
            is Int, is Long -> sb.append(value.toString())
            is Float, is Double -> {
                val d = (value as Number).toDouble()
                if (d.isNaN() || d.isInfinite()) sb.append("null") else sb.append(d.toString())
            }
            is Number -> sb.append(value.toString())
            is Map<*, *> -> writeObject(sb, value)
            is List<*> -> writeArray(sb, value)
            is Array<*> -> writeArray(sb, value.toList())
            else -> writeString(sb, value.toString())
        }
    }

    private fun writeObject(sb: StringBuilder, map: Map<*, *>) {
        sb.append('{')
        var first = true
        for ((k, v) in map) {
            if (!first) sb.append(',')
            first = false
            writeString(sb, k.toString())
            sb.append(':')
            writeValue(sb, v)
        }
        sb.append('}')
    }

    private fun writeArray(sb: StringBuilder, list: List<*>) {
        sb.append('[')
        var first = true
        for (v in list) {
            if (!first) sb.append(',')
            first = false
            writeValue(sb, v)
        }
        sb.append(']')
    }

    private fun writeString(sb: StringBuilder, s: String) {
        sb.append('"')
        for (c in s) {
            when (c) {
                '"' -> sb.append("\\\"")
                '\\' -> sb.append("\\\\")
                '\n' -> sb.append("\\n")
                '\r' -> sb.append("\\r")
                '\t' -> sb.append("\\t")
                else -> {
                    val code = c.toInt()
                    if (code < 0x20) {
                        sb.append("\\u").append(code.toString(16).padStart(4, '0'))
                    } else {
                        sb.append(c)
                    }
                }
            }
        }
        sb.append('"')
    }
}
