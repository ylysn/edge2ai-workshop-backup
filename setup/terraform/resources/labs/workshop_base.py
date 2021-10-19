#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Common utilities for Python scripts
"""
from nipyapi import canvas, versioning, nifi
from nipyapi.nifi.rest import ApiException

from . import *
from .utils import efm, schreg, nifireg, nifi as unifi, kafka, kudu, cdsw

PG_NAME = 'Process Sensor Data'
CONSUMER_GROUP_ID = 'iot-sensor-consumer'
PRODUCER_CLIENT_ID = 'nifi-sensor-data'


def skip_cdsw():
    flag = 'SKIP_CDSW' in os.environ
    LOG.debug('SKIP_CDSW={}'.format(flag))
    return flag


class BaseWorkshop(AbstractWorkshop):

    @classmethod
    def workshop_id(cls):
        """Return a short string to identify the CA type."""
        return 'base'

    def before_setup(self):
        self.context.root_pg, self.context.efm_pg_id, self.context.flow_id = unifi.set_environment()
        self.context.skip_cdsw = skip_cdsw()

    def after_setup(self):
        unifi.wait_for_data(PG_NAME)

    def teardown(self):
        root_pg, _, flow_id = unifi.set_environment()

        canvas.schedule_process_group(root_pg.id, False)
        while True:
            failed = False
            for controller in canvas.list_all_controllers(root_pg.id):
                try:
                    canvas.schedule_controller(controller, False)
                    LOG.debug('Controller %s stopped.', controller.component.name)
                except ApiException as exc:
                    if exc.status == 409 and 'is referenced by' in exc.body:
                        LOG.debug('Controller %s failed to stop. Will retry later.', controller.component.name)
                        failed = True
            if not failed:
                break

        unifi.delete_all(root_pg)
        efm.delete_all(flow_id)
        schreg.delete_all_schemas()
        reg_client = versioning.get_registry_client('NiFi Registry')
        if reg_client:
            versioning.delete_registry_client(reg_client)
        nifireg.delete_flows('SensorFlows')
        kudu.drop_table()

    def lab1_sensor_simulator(self):
        # Create a processor to run the sensor simulator
        gen_data = unifi.create_processor(
            self.context.root_pg, 'Generate Test Data', 'org.apache.nifi.processors.standard.ExecuteProcess',
            (0, 0),
            {
                'properties': {
                    'Command': 'python3',
                    'Command Arguments': '/opt/demo/simulate.py',
                },
                'schedulingPeriod': '1 sec',
                'schedulingStrategy': 'TIMER_DRIVEN',
                'autoTerminatedRelationships': ['success'],
            })
        canvas.schedule_processor(gen_data, True)

    def lab2_edge_flow(self):
        # Create input port and funnel in NiFi
        self.context.from_gw = canvas.create_port(
            self.context.root_pg.id, 'INPUT_PORT', 'from Gateway', 'STOPPED', (0, 200))
        self.context.temp_funnel = unifi.create_funnel(self.context.root_pg.id, (96, 350))
        canvas.create_connection(self.context.from_gw, self.context.temp_funnel)

        # Create flow in EFM
        self.context.consume_mqtt = efm.create_processor(
            self.context.flow_id, self.context.efm_pg_id,
            'ConsumeMQTT',
            'org.apache.nifi.processors.mqtt.ConsumeMQTT',
            (100, 100),
            {
                'Broker URI': 'tcp://edge2ai-1.dim.local:1883',
                'Client ID': 'minifi-iot',
                'Topic Filter': 'iot/#',
                'Max Queue Size': '60',
            })
        self.context.nifi_rpg = efm.create_remote_processor_group(
            self.context.flow_id, self.context.efm_pg_id, 'Remote PG', unifi.get_url(),
            'HTTP', (100, 400))
        self.context.consume_conn = efm.create_connection(
            self.context.flow_id, self.context.efm_pg_id, self.context.consume_mqtt, 'PROCESSOR',
            self.context.nifi_rpg,
            'REMOTE_INPUT_PORT', ['Message'], destination_port=self.context.from_gw.id,
            name='Sensor data', flow_file_expiration='60 seconds')

        # Create a bucket in NiFi Registry to save the edge flow versions
        if not versioning.get_registry_bucket('IoT'):
            versioning.create_registry_bucket('IoT')

        # Publish/version the flow
        efm.publish_flow(self.context.flow_id, 'First version - {}'.format(self.run_id))

    def lab3_register_schema(self):
        # Create Schema
        schreg.create_schema(
            'SensorReading', 'Schema for the data generated by the IoT sensors', schreg.read_in_schema())

    def lab4_nifi_flow(self):
        # Create a bucket in NiFi Registry to save the edge flow versions
        self.context.sensor_bucket = versioning.get_registry_bucket('SensorFlows')
        if not self.context.sensor_bucket:
            self.context.sensor_bucket = versioning.create_registry_bucket('SensorFlows')

        # Create NiFi Process Group
        self.context.reg_client = versioning.create_registry_client(
            'NiFi Registry', nifireg.get_url(), 'The registry...')
        self.context.sensor_pg = canvas.create_process_group(self.context.root_pg, PG_NAME, (330, 350))
        self.context.sensor_flow = nifireg.save_flow_ver(
            self.context.sensor_pg, self.context.reg_client, self.context.sensor_bucket,
            flow_name='SensorProcessGroup',
            comment='Enabled version control - {}'.format(self.run_id))

        # Update default SSL context controller service
        ssl_svc_name = 'Default NiFi SSL Context Service'
        if is_tls_enabled():
            props = {
                'SSL Protocol': 'TLS',
                'Truststore Type': 'JKS',
                'Truststore Filename': '/opt/cloudera/security/jks/truststore.jks',
                'Truststore Password': get_the_pwd(),
                'Keystore Type': 'JKS',
                'Keystore Filename': '/opt/cloudera/security/jks/keystore.jks',
                'Keystore Password': get_the_pwd(),
                'key-password': get_the_pwd(),
            }
            self.context.ssl_svc = canvas.get_controller(ssl_svc_name, 'name')
            if self.context.ssl_svc:
                canvas.schedule_controller(self.context.ssl_svc, False)
                self.context.ssl_svc = canvas.get_controller(ssl_svc_name, 'name')
                canvas.update_controller(self.context.ssl_svc, nifi.ControllerServiceDTO(properties=props))
                self.context.ssl_svc = canvas.get_controller(ssl_svc_name, 'name')
                canvas.schedule_controller(self.context.ssl_svc, True)
            else:
                self.context.keytab_svc = unifi.create_controller(
                    self.context.root_pg,
                    'org.apache.nifi.ssl.StandardRestrictedSSLContextService',
                    props, True,
                    name=ssl_svc_name)

        # Create controller services
        if is_tls_enabled():
            self.context.ssl_svc = canvas.get_controller(ssl_svc_name, 'name')
            props = {
                'Kerberos Keytab': '/keytabs/admin.keytab',
                'Kerberos Principal': 'admin',
            }
            self.context.keytab_svc = unifi.create_controller(
                self.context.sensor_pg,
                'org.apache.nifi.kerberos.KeytabCredentialsService',
                props,
                True)
        else:
            self.context.ssl_svc = None
            self.context.keytab_svc = None

        props = {
            'url': schreg.get_api_url(),
        }
        if is_tls_enabled():
            props.update({
                'kerberos-credentials-service': self.context.keytab_svc.id,
                'ssl-context-service': self.context.ssl_svc.id,
            })
        self.context.sr_svc = unifi.create_controller(
            self.context.sensor_pg, 'org.apache.nifi.schemaregistry.hortonworks.HortonworksSchemaRegistry',
            props,
            True)
        self.context.json_reader_svc = unifi.create_controller(
            self.context.sensor_pg, 'org.apache.nifi.json.JsonTreeReader',
            {
                'schema-access-strategy': 'schema-name',
                'schema-registry': self.context.sr_svc.id
            },
            True)
        self.context.json_writer_svc = unifi.create_controller(
            self.context.sensor_pg, 'org.apache.nifi.json.JsonRecordSetWriter',
            {
                'schema-access-strategy': 'schema-name',
                'schema-registry': self.context.sr_svc.id,
                'Schema Write Strategy': 'hwx-schema-ref-attributes'
            },
            True)
        self.context.avro_writer_svc = unifi.create_controller(
            self.context.sensor_pg, 'org.apache.nifi.avro.AvroRecordSetWriter',
            {
                'schema-access-strategy': 'schema-name',
                'schema-registry': self.context.sr_svc.id,
                'Schema Write Strategy': 'hwx-content-encoded-schema'
            },
            True)

        # Create flow
        sensor_port = canvas.create_port(self.context.sensor_pg.id, 'INPUT_PORT', 'Sensor Data', 'RUNNING', (0, 0))

        upd_attr = unifi.create_processor(self.context.sensor_pg, 'Set Schema Name',
                                          'org.apache.nifi.processors.attributes.UpdateAttribute', (0, 100),
                                          {
                                              'properties': {
                                                  'schema.name': 'SensorReading',
                                              },
                                          })
        canvas.create_connection(sensor_port, upd_attr)

        props = {
            'topic': 'iot',
            'record-reader': self.context.json_reader_svc.id,
            'record-writer': self.context.json_writer_svc.id,
        }
        props.update(kafka.get_common_client_properties(
            self.context, 'producer', CONSUMER_GROUP_ID, PRODUCER_CLIENT_ID))
        pub_kafka = unifi.create_processor(
            self.context.sensor_pg, 'Publish to Kafka topic: iot',
            'org.apache.nifi.processors.kafka.pubsub.PublishKafkaRecord_2_0',
            (0, 300),
            {
                'properties': props,
                'autoTerminatedRelationships': ['success'],
            })
        canvas.create_connection(upd_attr, pub_kafka, ['success'])

        fail_funnel = unifi.create_funnel(self.context.sensor_pg.id, (600, 343))
        canvas.create_connection(pub_kafka, fail_funnel, ['failure'])

        # Commit changes
        nifireg.save_flow_ver(self.context.sensor_pg, self.context.reg_client, self.context.sensor_bucket,
                              flow_id=self.context.sensor_flow.version_control_information.flow_id,
                              comment='First version - {}'.format(self.run_id))

        # Start flow
        canvas.schedule_process_group(self.context.root_pg.id, True)

        # Update "from Gateway" input port to connect to the process group
        unifi.update_connection(self.context.from_gw, self.context.temp_funnel, sensor_port)

    def lab6_expand_edge_flow(self):
        # Expand the CEM flow
        extract_proc = efm.create_processor(
            self.context.flow_id, self.context.efm_pg_id,
            'Extract sensor_0 and sensor1 values',
            'org.apache.nifi.processors.standard.EvaluateJsonPath',
            (500, 100),
            {
                'Destination': 'flowfile-attribute',
                'sensor_0': '$.sensor_0',
                'sensor_1': '$.sensor_1',
            },
            auto_terminate=['failure', 'unmatched', 'sensor_0', 'sensor_1'])
        filter_proc = efm.create_processor(
            self.context.flow_id, self.context.efm_pg_id,
            'Filter Errors',
            'org.apache.nifi.processors.standard.RouteOnAttribute',
            (500, 400),
            {
                'Routing Strategy': 'Route to Property name',
                'error': '${sensor_0:ge(500):or(${sensor_1:ge(500)})}',
            },
            auto_terminate=['error'])
        efm.delete_by_type(self.context.flow_id, self.context.consume_conn, 'connections')
        self.context.consume_conn = efm.create_connection(
            self.context.flow_id, self.context.efm_pg_id, self.context.consume_mqtt,
            'PROCESSOR', extract_proc, 'PROCESSOR', ['Message'],
            name='Sensor data',
            flow_file_expiration='60 seconds')
        efm.create_connection(
            self.context.flow_id, self.context.efm_pg_id, extract_proc,
            'PROCESSOR', filter_proc, 'PROCESSOR', ['matched'],
            name='Extracted attributes',
            flow_file_expiration='60 seconds')
        efm.create_connection(
            self.context.flow_id, self.context.efm_pg_id, filter_proc,
            'PROCESSOR', self.context.nifi_rpg, 'REMOTE_INPUT_PORT', ['unmatched'],
            destination_port=self.context.from_gw.id,
            name='Valid data',
            flow_file_expiration='60 seconds')

        # Publish/version flow
        efm.publish_flow(self.context.flow_id, 'Second version - {}'.format(self.run_id))

    def lab7_rest_and_kudu(self):
        # Create controllers
        self.context.json_reader_with_schema_svc = unifi.create_controller(
            self.context.sensor_pg,
            'org.apache.nifi.json.JsonTreeReader',
            {
                'schema-access-strategy': 'hwx-schema-ref-attributes',
                'schema-registry': self.context.sr_svc.id
            },
            True,
            name='JsonTreeReader - With schema identifier')
        props = {
            'rest-lookup-url': cdsw.get_altus_api_url() + '/models/call-model',
            'rest-lookup-record-reader': self.context.json_reader_svc.id,
            'rest-lookup-record-path': '/response'
        }
        if is_tls_enabled():
            props.update({
                'rest-lookup-ssl-context-service': self.context.ssl_svc.id,
            })
        rest_lookup_svc = unifi.create_controller(self.context.sensor_pg,
                                                  'org.apache.nifi.lookup.RestLookupService',
                                                  props,
                                                  True)

        # Build flow
        fail_funnel = unifi.create_funnel(self.context.sensor_pg.id, (1400, 340))

        props = {
            'topic': 'iot',
            'topic_type': 'names',
            'record-reader': self.context.json_reader_with_schema_svc.id,
            'record-writer': self.context.json_writer_svc.id,
        }
        props.update(kafka.get_common_client_properties(
            self.context, 'consumer', CONSUMER_GROUP_ID, PRODUCER_CLIENT_ID))
        consume_kafka = unifi.create_processor(
            self.context.sensor_pg, 'Consume Kafka iot messages',
            'org.apache.nifi.processors.kafka.pubsub.ConsumeKafkaRecord_2_0',
            (700, 0),
            {'properties': props})
        canvas.create_connection(consume_kafka, fail_funnel, ['parse.failure'])

        predict = unifi.create_processor(
            self.context.sensor_pg, 'Predict machine health',
            'org.apache.nifi.processors.standard.LookupRecord', (700, 200),
            {
                'properties': {
                    'record-reader': self.context.json_reader_with_schema_svc.id,
                    'record-writer': self.context.json_writer_svc.id,
                    'lookup-service': rest_lookup_svc.id,
                    'result-record-path': '/response',
                    'routing-strategy': 'route-to-success',
                    'result-contents': 'insert-entire-record',
                    'mime.type': "toString('application/json', 'UTF-8')",
                    'request.body':
                        "concat('{\"accessKey\":\"', '${cdsw.access.key}', "
                        "'\",\"request\":{\"feature\":\"', /sensor_0, ', ', "
                        "/sensor_1, ', ', /sensor_2, ', ', /sensor_3, ', ', "
                        "/sensor_4, ', ', /sensor_5, ', ', /sensor_6, ', ', "
                        "/sensor_7, ', ', /sensor_8, ', ', /sensor_9, ', ', "
                        "/sensor_10, ', ', /sensor_11, '\"}}')",
                    'request.method': "toString('post', 'UTF-8')",
                },
            })
        canvas.create_connection(predict, fail_funnel, ['failure'])
        canvas.create_connection(consume_kafka, predict, ['success'])

        update_health = unifi.create_processor(
            self.context.sensor_pg, 'Update health flag',
            'org.apache.nifi.processors.standard.UpdateRecord', (700, 400),
            {
                'properties': {
                    'record-reader': self.context.json_reader_with_schema_svc.id,
                    'record-writer': self.context.json_writer_svc.id,
                    'replacement-value-strategy': 'record-path-value',
                    '/is_healthy': '/response/result',
                },
            })
        canvas.create_connection(update_health, fail_funnel, ['failure'])
        canvas.create_connection(predict, update_health, ['success'])

        if (1, 14) <= kudu.get_version() < (1, 15):
            kudu_table_name = 'default.sensors'
        else:
            kudu_table_name = 'impala::default.sensors'
        write_kudu = unifi.create_processor(
            self.context.sensor_pg, 'Write to Kudu', 'org.apache.nifi.processors.kudu.PutKudu',
            (700, 600),
            {
                'properties': {
                    'Kudu Masters': get_hostname() + ':7051',
                    'Table Name': kudu_table_name,
                    'record-reader': self.context.json_reader_with_schema_svc.id,
                    'kerberos-credentials-service': self.context.keytab_svc.id
                    if is_tls_enabled() else None,
                },
            })
        canvas.create_connection(write_kudu, fail_funnel, ['failure'])
        canvas.create_connection(update_health, write_kudu, ['success'])

        props = {
            'topic': 'iot_enriched',
            'record-reader': self.context.json_reader_with_schema_svc.id,
            'record-writer': self.context.json_writer_svc.id,
        }
        props.update(kafka.get_common_client_properties(
            self.context, 'producer', CONSUMER_GROUP_ID, PRODUCER_CLIENT_ID))
        pub_kafka_enriched = unifi.create_processor(
            self.context.sensor_pg, 'Publish to Kafka topic: iot_enriched',
            'org.apache.nifi.processors.kafka.pubsub.PublishKafkaRecord_2_0',
            (300, 600),
            {
                'properties': props,
                'autoTerminatedRelationships': ['success', 'failure'],
            })
        canvas.create_connection(update_health, pub_kafka_enriched, ['success'])

        props = {
            'topic': 'iot_enriched_avro',
            'record-reader': self.context.json_reader_with_schema_svc.id,
            'record-writer': self.context.avro_writer_svc.id,
        }
        props.update(kafka.get_common_client_properties(
            self.context, 'producer', CONSUMER_GROUP_ID, PRODUCER_CLIENT_ID))
        pub_kafka_enriched_avro = unifi.create_processor(
            self.context.sensor_pg, 'Publish to Kafka topic: iot_enriched_avro',
            'org.apache.nifi.processors.kafka.pubsub.PublishKafkaRecord_2_0',
            (-100, 600),
            {
                'properties': props,
                'autoTerminatedRelationships': ['success', 'failure'],
            })
        canvas.create_connection(update_health, pub_kafka_enriched_avro, ['success'])

        monitor_activity = unifi.create_processor(
            self.context.sensor_pg, 'Monitor Activity',
            'org.apache.nifi.processors.standard.MonitorActivity', (700, 800),
            {
                'properties': {
                    'Threshold Duration': '45 secs',
                    'Continually Send Messages': 'true',
                },
                'autoTerminatedRelationships': ['activity.restored', 'success'],
            })
        canvas.create_connection(monitor_activity, fail_funnel, ['inactive'])
        canvas.create_connection(write_kudu, monitor_activity, ['success'])

        # Version flow
        nifireg.save_flow_ver(self.context.sensor_pg, self.context.reg_client, self.context.sensor_bucket,
                              flow_id=self.context.sensor_flow.version_control_information.flow_id,
                              comment='Second version - {}'.format(self.run_id))

        # Prepare Impala/Kudu table
        kudu.create_table()

        # Set the variable with the CDSW access key
        if not self.context.skip_cdsw:
            canvas.update_variable_registry(self.context.sensor_pg, [('cdsw.access.key', cdsw.get_model_access_key())])

        # Start everything
        canvas.schedule_process_group(self.context.root_pg.id, True)
