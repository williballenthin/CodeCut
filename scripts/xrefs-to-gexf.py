#!/usr/bin/env python3
'''
author: Willi Ballenthin
email: willi.ballenthin@gmail.com
'''
import os
import sys
import logging
from collections import namedtuple

import argparse
import networkx as nx

import idc
import idautils
import ida_funcs

logger = logging.getLogger(__name__)


Segment = namedtuple('Segment', ['start', 'end', 'name'])

def enum_segments():
    for segstart in idautils.Segments():
        segend = idc.SegEnd(segstart)
        segname = idc.SegName(segstart)
        yield Segment(segstart, segend, segname)


def enum_functions(range_):
    '''
    Args:
      range_ (Any): an instance with properties `start` and `end`.
    '''
    for funcea in idautils.Functions(range_.start, range_.end):
        yield funcea


FunctionChunk = namedtuple('FunctionChunk', ['start', 'end'])
def enum_chunks(fva):
    for start, end in idautils.Chunks(fva):
        yield FunctionChunk(start, end)


def enum_heads(range_):
    '''
    Args:
      range_ (Any): an instance with properties `start` and `end`.
    '''
    for head in idautils.Heads(range_.start, range_.end):
        yield head


def enum_insns(fva):
    for chunk in enum_chunks(fva):
        for insn in enum_heads(chunk):
            yield insn


XREF_DATA = 'data'
XREF_CODE = 'code'


def enum_edges():
    functions = set({})
    for segment in enum_segments():
        for function in enum_functions(segment):
            functions.add(function)

    for segment in enum_segments():
        logger.debug('segment: %s', segment.name)
        for function in enum_functions(segment):
            logger.debug('function: 0x%x', function)

            for insn in enum_insns(function):
                for xref in idautils.XrefsFrom(insn, flags=idaapi.XREF_FAR):
                    # call far, call near
                    if xref.type not in (idaapi.fl_CF, idaapi.fl_CN):
                        continue
                    # TODO: should calls to imports be included here?
                    # they act more like data references
                    yield (function, xref.to, XREF_CODE)

                for xref in idautils.DataRefsFrom(insn):
                    # TODO: call dword_AABBCCDD is included here. should it be?
                    yield (function, xref, XREF_DATA)


def extract_xref_graph():
    G = nx.DiGraph()

    edges = set([])
    functions = {}
    datas = {}

    names = {}
    logger.debug('fetching names...')
    for ea, name in idautils.Names():
        names[ea] = name

    logger.debug('fetching edges...')
    for src, dst, typ in enum_edges():
        G.add_edge(src, dst, edge_type=typ)

        # src is always function
        if src not in functions:
            functions[src] = names.get(src, 'sub_%x' % src)

        if typ == XREF_CODE:
            # dst is function
            if dst not in functions:
                functions[dst] = names.get(dst, 'sub_%x' % dst)

        else:
            # dst is data
            if dst not in datas:
                datas[dst] = names.get(dst, 'data_%x' % dst)

    for fva, name in functions.items():
        G.add_node(fva, address=fva, label=name, node_type='function')
    for dva, name in datas.items():
        G.add_node(dva, address=dva, label=name, node_type='data')

    return G


def main():
    logging.basicConfig(level=logging.DEBUG)
    logging.getLogger().setLevel(logging.DEBUG)

    logger.info('extracting cross references from .idb...')
    G = extract_xref_graph()

    path = os.environ.get('GEXF_PATH', idc.GetInputSHA256() + '.gexf')
    logger.info('writing output to: %s', path)
    nx.write_gexf(G, path)

    return 0


if __name__ == "__main__":
    main()
