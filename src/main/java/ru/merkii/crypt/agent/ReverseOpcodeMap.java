package ru.merkii.crypt.agent;

import ru.merkii.crypt.OpcodeTable;

import java.util.HashMap;
import java.util.Map;

final class ReverseOpcodeMap {

    static Map<Integer, Integer> build() {
        Map<Integer, Integer> substituteToOriginal = new HashMap<>();
        for (OpcodeTable.Entry entry : OpcodeTable.entries()) {
            substituteToOriginal.put(entry.substituteOpcode(), entry.originalOpcode());
        }
        return substituteToOriginal;
    }

    private ReverseOpcodeMap() {
    }
}
