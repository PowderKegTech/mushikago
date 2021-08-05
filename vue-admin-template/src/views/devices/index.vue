<template>
  <div class="app-container">
    <el-table
      v-loading="listLoading"
      :data="list"
      element-loading-text="Loading"
      border
      fit
      highlight-current-row
    >
      <el-table-column align="center" label="DeviceIP" prop= "id" width="120">
      </el-table-column>
      <el-table-column align="center" label="OpenPorts" width= "320">
	<template slot-scope="props">
           {{ props.row.ports}}<br>
        </template>
      </el-table-column>
      <el-table-column align="center" label="LocalAccounts" width= "320">
	<template slot-scope="props">
           {{ props.row.local_account_list}}<br>
        </template>
      </el-table-column>
      <el-table-column align="center" label="DomainAccounts" width= "320">
	<template slot-scope="props">
           {{ props.row.domain_account_list}}<br>
        </template>
      </el-table-column>
      <el-table-column align="center" label="Process" width= "320">
	<template slot-scope="props">
           {{ props.row.process_list}}<br>
        </template>
      </el-table-column>
      <el-table-column label="OS" prop="os" width="110" align="center">
      </el-table-column>
      <el-table-column label="Vendor" prop="vendor" width="110" align="center">
      </el-table-column>
      <el-table-column class-name="status-col" label="MACaddr" prop="mac" width="160" align="center">
      </el-table-column>
      <el-table-column align="center" prop="node_id" label="DeviceID" width="100">
      </el-table-column>
      <el-table-column align="center" label="LocalDrive" width= "320">
	<template slot-scope="props">
          {{ props.row.local_drive}}<br>
        </template>
      </el-table-column>
      <el-table-column align="center" label="LocalVulnerabilities" width= "320">
	<template slot-scope="props">
          {{ props.row.local_vuln_list}}<br>
        </template>
      </el-table-column>
      <el-table-column align="center" label="OS Patches" width= "320">
	<template slot-scope="props">
          {{ props.row.os_patches}}<br>
        </template>
      </el-table-column>
      <el-table-column label="NetstatInfo" prop="netstat_info" width="110" align="center">
      </el-table-column>
      <el-table-column align="center" label="ICS protocol" width= "320">
	<template slot-scope="props">
          {{ props.row.ics_protocol}}<br>
        </template>
      </el-table-column>
    </el-table>
  </div>
</template>

<script>
import { getList } from '@/api/table'
import * as d3 from 'd3'

export default {
  data() {
    return {
      list: [],	    
      listLoading: true
    }
  },
  created() {
    this.fetchData()
  },
  methods: {
    fetchData() {
      this.listLoading = true
      //getList().then(response => {
	d3.json('nodes.json').then((toriaezu) => {
	this.list = toriaezu.nodes
        console.log(JSON.stringify(toriaezu.nodes))

	//console.table(this.list.nodes,["id","os","ports","vendor"])
        this.listLoading = false
      })
      //this.listLoading = tmp
      //console.log(this)

    }
  }
}
</script>
