/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package snmpagent;

import java.io.File;
import java.io.IOException;
import org.snmp4j.TransportMapping;
import org.snmp4j.agent.BaseAgent;
import org.snmp4j.agent.CommandProcessor;
import org.snmp4j.agent.DuplicateRegistrationException;
import org.snmp4j.agent.MOGroup;
import org.snmp4j.agent.ManagedObject;
import org.snmp4j.agent.mo.MOTableRow;
import org.snmp4j.agent.mo.snmp.RowStatus;
import org.snmp4j.agent.mo.snmp.SnmpCommunityMIB;
import org.snmp4j.agent.mo.snmp.SnmpNotificationMIB;
import org.snmp4j.agent.mo.snmp.SnmpTargetMIB;
import org.snmp4j.agent.mo.snmp.StorageType;
import org.snmp4j.agent.mo.snmp.VacmMIB;
import org.snmp4j.agent.security.MutableVACM;
import org.snmp4j.mp.MPv3;
import org.snmp4j.security.SecurityLevel;
import org.snmp4j.security.SecurityModel;
import org.snmp4j.security.USM;
import org.snmp4j.smi.Address;
import org.snmp4j.smi.GenericAddress;
import org.snmp4j.smi.Integer32;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.Variable;
import org.snmp4j.transport.TransportMappings;

public class SNMPAgent extends BaseAgent {
    private String address ;



public SNMPAgent(String address) throws IOException {



super(new File("conf.agent"), new File("bootCounter.agent"),
                new CommandProcessor(
                        new OctetString(MPv3.createLocalEngineID())));
        this.address = address;
    }

/**

     * Adds community to security name mappings needed for SNMPv1 and SNMPv2c.

     */

    @Override


    protected void addCommunities(SnmpCommunityMIB communityMIB) {

        Variable[] com2sec = new Variable[] { new OctetString("public"),
                new OctetString("cpublic"), // security name
                getAgent().getContextEngineID(), // local engine ID
                new OctetString("public"), // default context name
                new OctetString(), // transport tag
                new Integer32(StorageType.nonVolatile), // storage type
                new Integer32(RowStatus.active) // row status
        };
        MOTableRow row = communityMIB.getSnmpCommunityEntry().createRow(
                new OctetString("public2public").toSubIndex(true), com2sec);
        communityMIB.getSnmpCommunityEntry().addRow((SnmpCommunityMIB.SnmpCommunityEntryRow) row);

    }

    @Override
    protected void addNotificationTargets(SnmpTargetMIB arg0,
            SnmpNotificationMIB arg1) {
        // TODO Auto-generated method stub
    }
 

    @Override
    protected void addUsmUser(USM arg0) {
        // TODO Auto-generated method stub
    }

    /**
98
     * Adds initial VACM configuration.
99
     */
    @Override
    protected void addViews(VacmMIB vacm) {
        vacm.addGroup(SecurityModel.SECURITY_MODEL_SNMPv2c, new OctetString(
                "cpublic"), new OctetString("v1v2group"),
                StorageType.nonVolatile);
        vacm.addAccess(new OctetString("v1v2group"), new OctetString("public"),
                SecurityModel.SECURITY_MODEL_ANY, SecurityLevel.NOAUTH_NOPRIV,
                MutableVACM.VACM_MATCH_EXACT, new OctetString("fullReadView"),
                new OctetString("fullWriteView"), new OctetString(
                        "fullNotifyView"), StorageType.nonVolatile);
 
        vacm.addViewTreeFamily(new OctetString("fullReadView"), new OID("1.3"),
                new OctetString(), VacmMIB.vacmViewIncluded,
                StorageType.nonVolatile);
    }
	
	


 

    /**
119
     * Unregister the basic MIB modules from the agent's MOServer.
120
     */

    @Override

    protected void unregisterManagedObjects() {

        // TODO Auto-generated method stub
    }

 
    /**
128
     * Register additional managed objects at the agent's server.
129
     */

    @Override

    protected void registerManagedObjects() {

        // TODO Auto-generated method stub

 

    }

    protected void initTransportMappings() throws IOException {

        transportMappings = new TransportMapping[1];

        Address addr = GenericAddress.parse(address);
        TransportMapping tm = TransportMappings.getInstance()
                .createTransportMapping(addr);
        transportMappings[0] = tm;
    }
 
    /**
     * Start method invokes some initialization methods needed to start the
     * agent
     *
     * @throws IOException
     */
  /*  public void start() throws IOException {

        init();

        // This method reads some old config from a file and causes

        // unexpected behavior.

        // loadConfig(ImportModes.REPLACE_CREATE);

        addShutdownHook();

        getServer().addContext(new OctetString("public"));

        finishInit();

        run();

        sendColdStartNotification();

    }*/
    public void start() throws IOException {
		init();
		addShutdownHook();
        unregisterManagedObject(this.getSnmpv2MIB());
        getServer().addContext(new OctetString("public"));
        finishInit();
        run();
        sendColdStartNotification();
                System.out.println("Snmp Get Response = " ); 
	}
    
    
	public void registerManagedObject(ManagedObject mo) {
		try {
			server.register(mo, null);
			}
		catch (DuplicateRegistrationException ex) {
		throw new RuntimeException(ex);
		  }
        }
        
 

    /**

     * Clients can register the MO they need

     */

 

 

    public void unregisterManagedObject(MOGroup moGroup) {

        moGroup.unregisterMOs(server, getContext(moGroup));
    }
    
 


 static final OID sysDescr = new OID(".1.3.6.1.2.1.1.0");
 static final OID ss1 = new OID(".1.3.6.1.2.1.2.0");
 static final OID ssoid = new OID(".1.3.6.1.2.1.3.0");
 static final OID sstime = new OID(".1.3.6.1.2.1.4.0");
 static final OID ss2 = new OID(".1.3.6.1.2.1.5.0");
 static final OID ssinteger = new OID(".1.3.6.1.2.1.6.0");
    public static void main(String[] args) throws IOException, DuplicateRegistrationException {
      SNMPAgent agent = new SNMPAgent("127.0.0.1/9994");
      agent.start();
      agent.unregisterManagedObject(agent.getSnmpv2MIB());
      agent.registerManagedObject(MOCreator.createReadOnly(sysDescr,"This Description is set By Azza and Hanan"));
      agent.registerManagedObject(MOCreator.createReadOnly(ss1,"Hardware: Intel64 Family 6 Model 69 Stepping 1 AT/AT COMPATIBLE - Software: Windows Version 6.3 (Build 16299 Multiprocessor Free)"));
      agent.registerManagedObject(MOCreator.createReadOnly(ssoid,"iso.3.6.1.4.1.311.1.1.3.1.1"));
      agent.registerManagedObject(MOCreator.createReadOnly(sstime,"(2212035) 6:08:40.35"));
      agent.registerManagedObject(MOCreator.createReadOnly(ss2,"dell-PC"));
      agent.registerManagedObject(MOCreator.createReadOnly(ssinteger,"76"));
      int x = System.in.read();
    }

}



