#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
from core.alert import messages
import logging

logger = logging.getLogger("__name__")
# logger.setLevel(logging.INFO)

# for console output; don't use print
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
consoleHandler = logging.StreamHandler()
logger.addHandler(consoleHandler)


def start(events):
    """
    generate the d3_tree_v1_graph with events

    Args:
        events: all events

    Returns:
        a graph in HTML
    """

    # define  a normalised_json
    normalisedjson = {
        "name": "Started attack",
        "children": {}
    }
    # get data for normalised_json
    # logger.debug(f"d3_engine: event {events}")

    for event in events:
        if event['target'] not in normalisedjson['children']:
            normalisedjson['children'].update(
                {
                    event['target']: {}
                }
            )
            normalisedjson['children'][event['target']].update(
                {
                    event['module_name']: []
                }
            )

        if event['module_name'] not in normalisedjson['children'][event['target']]:
            normalisedjson['children'][event['target']].update(
                {
                    event['module_name']: []
                }
            )
        normalisedjson['children'][event['target']][event['module_name']].append(
            f"target: {event['target']}, module_name: {event['module_name']}, port: "
            f"{event['port']}, event: {event['event']}"
        )

    # define a d3_structure_json
    d3_structure = {
        "name": "assets",
        "children": []
    }
    # get data for normalised_json
    # logger.debug(f"d3_graph: normalized json: {normalisedjson}")
    for target in list(normalisedjson['children'].keys()):
        children_array = []
        for module_name in list(normalisedjson['children'][target].keys()):
            for description in normalisedjson["children"][target][module_name]:
                #children_array = [
                #    {
                #        "name": module_name,
                #        "children": [
                #            {
                #                "name": description
                #            }
                #        ]
                #    }
                #]
                children_array.append(
                    {
                        "name": module_name,
                        "children": [
                            {
                                "name": description
                            }
                        ]
                    }
                )
                #d3_structure["children"].append(
                #    {
                #       "name": target,
                #       "children": children_array
                #   }
                #)
        d3_structure["children"].append(
            {
                "name": target,
                "children": children_array
             }
        )
    logger.debug(f"d3_structure: {d3_structure}")
    from config import nettacker_paths
    data = open(
        os.path.join(
            nettacker_paths()['web_static_files_path'],
            'report/d3_tree_v1.html'
        )
    ).read().replace(
        '__data_will_locate_here__',
        json.dumps(d3_structure)
    ).replace(
        '__title_to_replace__',
        messages("pentest_graphs")
    ).replace(
        '__description_to_replace__',
        messages("graph_message")
    ).replace(
        '__html_title_to_replace__',
        messages("nettacker_report")
    )
    return data
